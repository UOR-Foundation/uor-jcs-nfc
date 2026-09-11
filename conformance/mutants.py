#!/usr/bin/env python3
"""
mutants.py — condition-removed mutant generators for the `uor-jcs-nfc` corpus.

A conformance checker refuses to count a check family as exercised unless it registers a
condition-removed mutant generator; an assertion-free check fails CI. A check that
cannot fail is not a check — the audited implementation's `reserialize()` no-op
passed every idempotence assertion because idempotence on a no-op is trivially true.

Each mutant removes exactly one condition from the reference implementation. The
corpus must then FAIL, and the specific vectors named in `catches` must be the ones
that fail. A mutant no vector catches is an unexercised check family.

    python run_mutants.py uor-jcs-nfc-vectors-v0.1-rc5.json
"""

import json, re, unicodedata

import uor_jcs_nfc_ref as ref


# --------------------------------------------------------------------------
# Each entry: (id, description, apply_fn, expected_catches)
#
# `apply_fn` monkeypatches the reference module in place. `run_mutants.py`
# restores originals between mutants.
# --------------------------------------------------------------------------

def _m_value_based_admission():
    """THE mutant. Replace the lexical token test with a value test.

    This reproduces the audited defect exactly: a type/value guard admitted
    float(2**53) while rejecting the integer 2**53. Under this mutant every
    decimal or exponent token whose value is integral is admitted.
    """
    def float_hook(tok):
        v = float(tok)
        if v.is_integer() and abs(v) <= ref.SAFE:
            return int(v)
        raise ref.Refused("E_NUM_TOKEN", tok)
    ref._float_hook = float_hook


def _m_type_based_guard():
    """Range check on the converted value's type rather than the token."""
    def int_hook(tok):
        v = int(tok)
        if not isinstance(v, int):
            raise ref.Refused("E_NUM_TOKEN", tok)
        return v
    ref._int_hook = int_hook


def _m_no_leading_zero_check():
    """Accept any token int() can parse — drops the grammar."""
    def int_hook(tok):
        v = int(tok)
        if abs(v) > ref.SAFE:
            raise ref.Refused("E_NUM_RANGE", tok)
        return v
    ref._int_hook = int_hook


def _m_range_on_value_not_token():
    """Bound-check a float conversion, which loses precision at the boundary."""
    def int_hook(tok):
        if not ref.INT_TOKEN.match(tok):
            raise ref.Refused("E_NUM_TOKEN", tok)
        if abs(float(tok)) > float(ref.SAFE):
            raise ref.Refused("E_NUM_RANGE", tok)
        return int(tok)
    ref._int_hook = int_hook


def _m_drop_duplicate_detection():
    """No object_pairs_hook — last member silently wins."""
    ref._scan_duplicates = lambda v: None
    ref._pairs_hook = lambda pairs: dict(pairs)


def _m_compare_names_before_escape_decode():
    """Compare raw source spellings, so "a" and "\\u0061" look distinct."""
    def pairs_hook(pairs):
        return ref._ParsedObject(pairs, [])
    ref._pairs_hook = pairs_hook
    ref._scan_duplicates = lambda v: None


def _m_no_bom_check():
    """Decode with utf-8-sig, silently eating a byte-order mark."""
    orig = ref.admit
    def admit(data):
        if data.startswith(b"\xef\xbb\xbf"):
            data = data[3:]
        return orig(data)
    ref.admit = admit


def _m_no_surrogate_scan():
    """Escaped lone surrogates pass — CPython's parser admits them."""
    ref._scan_surrogates = lambda v: None


def _m_scan_values_not_names():
    """Scan string values but not member names."""
    def scan(v):
        if isinstance(v, str):
            for ch in v:
                if 0xD800 <= ord(ch) <= 0xDFFF:
                    raise ref.Refused("E_SURROGATE", repr(ch))
        elif isinstance(v, dict):
            for val in v.values():
                scan(val)
        elif isinstance(v, list):
            for x in v:
                scan(x)
    ref._scan_surrogates = scan


def _m_reject_all_surrogate_escapes():
    """Over-rejection: refuse valid pairs too. Must break the ACCEPT vectors."""
    def scan(v):
        if isinstance(v, str):
            for ch in v:
                if 0x1F000 <= ord(ch) <= 0x1FAFF or 0xD800 <= ord(ch) <= 0xDFFF:
                    raise ref.Refused("E_SURROGATE", repr(ch))
        elif isinstance(v, dict):
            for k, val in v.items():
                scan(k); scan(val)
        elif isinstance(v, list):
            for x in v:
                scan(x)
    ref._scan_surrogates = scan


def _m_no_trailing_check():
    """json.loads instead of raw_decode + remainder."""
    orig = ref.admit
    def admit(data):
        if data.startswith(b"\xef\xbb\xbf"):
            raise ref.Refused("E_BOM")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as e:
            raise ref.Refused("E_UTF8", e.reason)
        dec = json.JSONDecoder(parse_int=ref._int_hook, parse_float=ref._float_hook,
                               parse_constant=ref._const_hook,
                               object_pairs_hook=ref._pairs_hook)
        try:
            value, _ = dec.raw_decode(text, len(text) - len(text.lstrip(" \t\r\n")))
        except ref.Refused:
            raise
        except ValueError as e:
            raise ref.Refused("E_JSON", str(e))
        ref._scan_duplicates(value); ref._scan_surrogates(value)
        return value
    ref.admit = admit


def _m_nfc_after_sort():
    """THE ordering mutant. Sort on raw names, then normalize.

    Removes exactly one condition: the ordering of NFC relative to member sort.
    Collision refusal is PRESERVED, so this mutant is caught only by the ordering
    vector and not by the collision vector. An earlier revision dropped both and
    was therefore a two-condition mutant, which is not a valid probe.
    """
    def canon(value):
        def enc(v):
            if isinstance(v, dict):
                keys = sorted(v, key=lambda k: k.encode("utf-16-be"))   # raw order
                seen = {}
                for k in keys:
                    nk = unicodedata.normalize("NFC", k)
                    if nk in seen:                                      # PRESERVED
                        raise ref.Refused("E_NFC_COLLISION", f"{k!r} -> {nk!r}")
                    seen[nk] = True
                return "{" + ",".join(
                    f"{ref._jcs_string(unicodedata.normalize('NFC', k))}:{enc(v[k])}"
                    for k in keys) + "}"
            if isinstance(v, list):
                return "[" + ",".join(enc(x) for x in v) + "]"
            if isinstance(v, str):
                return ref._jcs_string(unicodedata.normalize("NFC", v))
            return ref._encode(v)
        return enc(value)
    ref.canonicalize = canon


def _m_nfc_names_only():
    """Normalize member names but not string values."""
    def nfc(v):
        if isinstance(v, dict):
            out = {}
            for k, val in v.items():
                nk = unicodedata.normalize("NFC", k)
                if nk in out:
                    raise ref.Refused("E_NFC_COLLISION", nk)
                out[nk] = nfc(val)
            return out
        if isinstance(v, list):
            return [nfc(x) for x in v]
        return v
    ref.canonicalize = lambda value: ref._encode(nfc(value))


def _m_no_nfc_at_all():
    """Plain JCS with no normalization — i.e. the `jcs` profile."""
    ref.canonicalize = lambda value: ref._encode(value)


def _m_collision_last_wins():
    """Merge post-NFC colliding names instead of refusing.

    Silently discards a member the digest claims to identify.
    """
    def nfc(v):
        if isinstance(v, str):
            return unicodedata.normalize("NFC", v)
        if isinstance(v, list):
            return [nfc(x) for x in v]
        if isinstance(v, dict):
            return {unicodedata.normalize("NFC", k): nfc(val) for k, val in v.items()}
        return v
    ref.canonicalize = lambda value: ref._encode(nfc(value))


def _m_sort_by_code_point():
    """Sort by Unicode code point rather than UTF-16 code units.

    Agrees for the entire BMP; diverges above it.
    """
    orig = ref._encode
    def encode(v):
        if isinstance(v, dict):
            keys = sorted(v)                     # code-point order
            return "{" + ",".join(
                f"{ref._jcs_string(k)}:{encode(v[k])}" for k in keys) + "}"
        if isinstance(v, list):
            return "[" + ",".join(encode(x) for x in v) + "]"
        return orig(v)
    ref._encode = encode
    ref.canonicalize = lambda value: encode(ref._nfc(value))


def _m_ensure_ascii():
    """Escape non-ASCII as \\uXXXX instead of emitting raw UTF-8."""
    def jcs_string(s):
        out = ['"']
        for ch in s:
            if ch in ref._ESC:
                out.append(ref._ESC[ch])
            elif ord(ch) < 0x20 or ord(ch) > 0x7E:
                if ord(ch) > 0xFFFF:
                    c = ord(ch) - 0x10000
                    out.append("\\u%04x\\u%04x" % (0xD800 + (c >> 10),
                                                   0xDC00 + (c & 0x3FF)))
                else:
                    out.append("\\u%04x" % ord(ch))
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    ref._jcs_string = jcs_string


def _m_uppercase_hex_escapes():
    """Emit \\u001B rather than \\u001b."""
    def jcs_string(s):
        out = ['"']
        for ch in s:
            if ch in ref._ESC:
                out.append(ref._ESC[ch])
            elif ord(ch) < 0x20:
                out.append("\\u%04X" % ord(ch))
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    ref._jcs_string = jcs_string


def _m_long_form_escapes():
    """Use \\u0009 where RFC 8785 requires the named escape \\t."""
    def jcs_string(s):
        out = ['"']
        for ch in s:
            if ch in ('"', "\\"):
                out.append("\\" + ch)
            elif ord(ch) < 0x20:
                out.append("\\u%04x" % ord(ch))
            else:
                out.append(ch)
        out.append('"')
        return "".join(out)
    ref._jcs_string = jcs_string


def _m_drop_empty_members():
    """Remove null / [] / {} bottom-up — the behavior of the withdrawn jcs-n.

    Makes 'absent' and 'present-but-empty' indistinguishable.
    """
    def strip(v):
        if isinstance(v, dict):
            return {k: strip(x) for k, x in v.items()
                    if x is not None and x != [] and x != {}}
        if isinstance(v, list):
            return [strip(x) for x in v]
        return v
    orig = ref.canonicalize
    ref.canonicalize = lambda value: orig(strip(value))


def _m_reserialize_noop():
    """The historical defect: a round-trip control that returns its input.

    Passes every idempotence assertion because idempotence on a no-op is
    trivially true. Included to demonstrate that no corpus vector catches it —
    only a mutation probe can.
    """
    ref.reserialize = lambda s: s


MUTANTS = [
 ("MUT-01-value-based-admission", _m_value_based_admission,
  ["admit-fail-num-02", "admit-fail-num-03", "admit-fail-num-04",
   "admit-fail-num-05", "admit-fail-num-06"],
  "reproduces the audited defect: float(2**53) admitted while 2**53 rejected"),
 ("MUT-02-type-based-guard", _m_type_based_guard,
  ["admit-fail-rng-01", "admit-fail-rng-02"],
  "admit-fail-json-01 is NOT predicted: 01 is refused by the host parser before "
  "any number hook runs, so this mutant cannot change its outcome."),
 ("MUT-03-no-grammar-check", _m_no_leading_zero_check, [],
  "EXPECTED SURVIVOR: CPython's JSON scanner only ever hands parse_int tokens "
  "already matching -?(0|[1-9][0-9]*), so INT_TOKEN.match can never fail. The "
  "grammar check is unreachable defensive code in THIS host parser. A host with "
  "a laxer scanner would need it. Documented, not removed."),
 ("MUT-04-range-on-value", _m_range_on_value_not_token, [],
  "EQUIVALENT MUTANT: binary64 is exact through 2^53, so a value-based bound "
  "test and a token-based one agree at every reachable boundary. Behaviourally "
  "indistinguishable, not an untested check."),
 ("MUT-05-no-duplicate-detection", _m_drop_duplicate_detection,
  ["admit-fail-str-01", "admit-fail-str-02", "admit-fail-str-02b"], ""),
 ("MUT-06-compare-before-escape-decode", _m_compare_names_before_escape_decode,
  ["admit-fail-str-01", "admit-fail-str-02", "admit-fail-str-02b"], ""),
 ("MUT-07-no-bom-check", _m_no_bom_check, ["admit-fail-str-05"], ""),
 ("MUT-08-no-surrogate-scan", _m_no_surrogate_scan,
  ["admit-fail-str-07", "admit-fail-str-08", "admit-fail-str-09"], ""),
 ("MUT-09-scan-values-not-names", _m_scan_values_not_names,
  ["admit-fail-str-08"], ""),
 ("MUT-10-reject-all-surrogates", _m_reject_all_surrogate_escapes,
  ["admit-ok-11", "admit-ok-12", "uor-jcs-nfc-kat-06"],
  "over-rejection: caught only by ACCEPT vectors"),
 ("MUT-11-no-trailing-check", _m_no_trailing_check,
  ["admit-fail-str-03", "admit-fail-str-04"], ""),
 ("MUT-12-nfc-after-sort", _m_nfc_after_sort,
  ["uor-jcs-nfc-kat-05"],
  "the class CPB's jcs-n note recorded as uncovered by any published corpus"),
 ("MUT-13-nfc-names-only", _m_nfc_names_only,
  ["uor-jcs-nfc-kat-04"], ""),
 ("MUT-14-no-nfc", _m_no_nfc_at_all,
  ["uor-jcs-nfc-kat-02", "uor-jcs-nfc-kat-04", "uor-jcs-nfc-kat-05",
   "uor-jcs-nfc-fail-03"],
  "equivalent to the `jcs` profile. Removing normalization necessarily removes "
  "post-NFC collision detection and the NFC-dependent sort order -- those are "
  "consequences of the single removed condition, not separate removals."),
 ("MUT-15-collision-last-wins", _m_collision_last_wins,
  ["uor-jcs-nfc-fail-03"], ""),
 ("MUT-16-sort-by-code-point", _m_sort_by_code_point,
  ["uor-jcs-nfc-kat-06"], "diverges only above the BMP"),
 ("MUT-17-ensure-ascii", _m_ensure_ascii,
  ["uor-jcs-nfc-kat-02", "uor-jcs-nfc-kat-03", "uor-jcs-nfc-kat-04",
   "uor-jcs-nfc-kat-04b", "uor-jcs-nfc-kat-05", "uor-jcs-nfc-kat-06",
   "uor-jcs-nfc-kat-13"],
  "every vector carrying a non-ASCII character changes, which is all seven"),
 ("MUT-18-uppercase-hex", _m_uppercase_hex_escapes,
  ["uor-jcs-nfc-kat-07"], ""),
 ("MUT-19-long-form-escapes", _m_long_form_escapes,
  ["uor-jcs-nfc-kat-07"], ""),
 ("MUT-20-drop-empty-members", _m_drop_empty_members,
  ["uor-jcs-nfc-kat-08"], "the behavior of the withdrawn jcs-n"),
 ("MUT-21-reserialize-noop", _m_reserialize_noop, [],
  "EXPECTED SURVIVOR: no corpus vector can catch this. Documents the limit."),
]
