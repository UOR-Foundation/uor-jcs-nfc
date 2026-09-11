#!/usr/bin/env python3
"""
uor_jcs_nfc_ref.py — reference implementation of the `uor-jcs-nfc` digest context.

Written from SPEC.md, NOT derived from any existing implementation. Its purpose is to
generate vector expected values so the vectors are the oracle and implementations conform
to them, rather than an implementation becoming the oracle.

Normalization uses Unicode 15.0.0 (SPEC.md §1.3); a different Unicode version implements
a different digest context.

Stages, per SPEC.md §1:
    admit(bytes) -> JsonValue          lexical + structural admission
    canonicalize(JsonValue) -> str     NFC before sort, collision reject, JCS encode
    digest(str) -> "sha256:<hex>"      SHA-256, lowercase hex
"""

import hashlib, json, re, unicodedata

INT_TOKEN = re.compile(r"^-?(0|[1-9][0-9]*)$")
SAFE = 9007199254740991


class Refused(Exception):
    def __init__(self, code, detail=""):
        self.code = code
        super().__init__(f"{code}: {detail}" if detail else code)


# ---------------------------------------------------------------- admission

def _int_hook(tok):
    if not INT_TOKEN.match(tok):
        raise Refused("E_NUM_TOKEN", tok)
    v = int(tok)
    if abs(v) > SAFE:
        raise Refused("E_NUM_RANGE", tok)
    return v


def _float_hook(tok):
    raise Refused("E_NUM_TOKEN", tok)


def _const_hook(name):
    raise Refused("E_CONSTANT", name)


class _ParsedObject(dict):
    """Dict carrying duplicate findings until trailing-content precedence is settled."""

    def __init__(self, pairs, duplicates):
        super().__init__(pairs)
        self.duplicates = duplicates


def _pairs_hook(pairs):
    # Names arrive AFTER escape decoding, BEFORE NFC -- the correct comparison point.
    # Do not raise here: E_TRAILING has precedence over E_DUP_NAME in UOR-ADMIT.
    seen = set()
    duplicates = []
    for k, _ in pairs:
        if k in seen:
            duplicates.append(k)
        seen.add(k)
    return _ParsedObject(pairs, duplicates)


def _scan_duplicates(v):
    if isinstance(v, _ParsedObject):
        if v.duplicates:
            raise Refused("E_DUP_NAME", v.duplicates[0])
        for child in v.values():
            _scan_duplicates(child)
    elif isinstance(v, list):
        for child in v:
            _scan_duplicates(child)


def _scan_surrogates(v):
    """Recursive over member names and string values. Escaped lone surrogates are
    admitted by CPython's parser and must be rejected explicitly."""
    if isinstance(v, str):
        for ch in v:
            if 0xD800 <= ord(ch) <= 0xDFFF:
                raise Refused("E_SURROGATE", repr(ch))
    elif isinstance(v, dict):
        for k, val in v.items():
            _scan_surrogates(k)
            _scan_surrogates(val)
    elif isinstance(v, list):
        for item in v:
            _scan_surrogates(item)


def admit(data):
    if not isinstance(data, bytes):
        raise TypeError("admit() takes raw bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise Refused("E_BOM")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise Refused("E_UTF8", e.reason)

    dec = json.JSONDecoder(parse_int=_int_hook, parse_float=_float_hook,
                           parse_constant=_const_hook,
                           object_pairs_hook=_pairs_hook)
    try:
        # raw_decode does not skip leading JSON whitespace.
        start = len(text) - len(text.lstrip(" \t\r\n"))
        value, end = dec.raw_decode(text, start)
    except Refused:
        raise
    except ValueError as e:
        raise Refused("E_JSON", str(e))

    if text[end:].strip():
        raise Refused("E_TRAILING", repr(text[end:][:20]))

    _scan_duplicates(value)
    _scan_surrogates(value)
    return value


# ----------------------------------------------------------- canonicalization

_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
        "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _jcs_string(s):
    out = ['"']
    for ch in s:
        if ch in _ESC:
            out.append(_ESC[ch])
        elif ord(ch) < 0x20:
            out.append("\\u%04x" % ord(ch))     # lowercase hex, RFC 8785 3.2.2.2
        else:
            out.append(ch)                       # raw UTF-8, no ASCII escaping
    out.append('"')
    return "".join(out)


def _nfc(v):
    """NFC over member names and string values, recursively, BEFORE sort."""
    if isinstance(v, str):
        return unicodedata.normalize("NFC", v)
    if isinstance(v, list):
        return [_nfc(x) for x in v]
    if isinstance(v, dict):
        out = {}
        for k, val in v.items():
            nk = unicodedata.normalize("NFC", k)
            if nk in out:
                raise Refused("E_NFC_COLLISION", f"{k!r} -> {nk!r}")
            out[nk] = _nfc(val)
        return out
    return v


def _encode(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        return str(v)                            # -0 parsed to 0, emits "0"
    if isinstance(v, str):
        return _jcs_string(v)
    if isinstance(v, list):
        return "[" + ",".join(_encode(x) for x in v) + "]"
    if isinstance(v, dict):
        # sort by UTF-16 code units of the unescaped, NFC-normalized name
        keys = sorted(v, key=lambda k: k.encode("utf-16-be"))
        return "{" + ",".join(f"{_jcs_string(k)}:{_encode(v[k])}" for k in keys) + "}"
    raise Refused("E_JSON", f"unencodable {type(v).__name__}")


def canonicalize(value):
    return _encode(_nfc(value))


def digest(canon_str):
    return "sha256:" + hashlib.sha256(canon_str.encode("utf-8")).hexdigest()


def address_json(data):
    c = canonicalize(admit(data))
    return c, digest(c)
