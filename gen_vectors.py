#!/usr/bin/env python3
"""Generate the uor-jcs-nfc two-sided vector set with C7 fields."""
import datetime, hashlib, json, platform, sys, unicodedata
from pathlib import Path
from uor_jcs_nfc_ref import admit, canonicalize, digest, Refused

PINNED_UNICODE = "15.0.0"          # SPEC.md 1.3, normative
if unicodedata.unidata_version != PINNED_UNICODE:
    raise SystemExit(
        f"refusing to generate: runtime Unicode {unicodedata.unidata_version} != "
        f"pinned {PINNED_UNICODE} (SPEC.md 1.3). A corpus generated under a different "
        f"Unicode version describes a different digest context."
    )

V = []

def add(vid, layer, mode, normative, kind, src, note, hexin=None):
    rec = {"id": vid, "layer": layer, "evidence_mode": mode,
           "normative": normative, "kind": kind, "asserts": note}
    raw = bytes.fromhex(hexin) if hexin else src.encode("utf-8")
    if hexin: rec["input_hex"] = hexin
    else:     rec["input_json"] = src
    try:
        value = admit(raw)
        canon = canonicalize(value)
        if kind == "reject":
            rec["ERROR"] = "expected refusal, was admitted"
        elif layer == A:
            # Admission positives assert admission only. A digest here would
            # silently turn a stage-local vector into a composition vector.
            rec["expected_result"] = "ADMITTED"
        else:
            rec["canonical_json"] = canon
            rec["expected_digest"] = digest(canon)
            rec["expected_result"] = "MATCH"
    except Refused as e:
        if kind == "accept":
            rec["ERROR"] = f"expected admission, refused {e.code}"
        else:
            rec["expected_result"] = "REFUSED"
            rec["expected_code"] = e.code
    V.append(rec)

A, S, N = "admissibility", "self", True
RP, LF = "ruleset_profile", "leaf_function"

# ---- admissibility: accept -------------------------------------------------
for vid, src, note in [
 ("admit-ok-01", '{"n":0}', "zero"),
 ("admit-ok-02", '{"n":-0}', "negative zero admitted; canonicalization to 0 is kat-11"),
 ("admit-ok-03", '{"n":9007199254740991}', "upper bound inclusive"),
 ("admit-ok-04", '{"n":-9007199254740991}', "lower bound inclusive"),
 ("admit-ok-05", '{"n":-1}', "negative integer"),
 ("admit-ok-06", '{"a":1,"b":2}', "baseline"),
 ("admit-ok-07", '{"A\u030A":1}', "NFD name admitted; normalization is downstream"),
 ("admit-ok-08", '{"a":null,"b":[],"c":{},"d":""}', "empty values admitted"),
 ("admit-ok-09", '{"a":1}   ', "trailing whitespace admissible"),
 ("admit-ok-10", '{"o":{"z":0,"a":[true,null,"x"]}}', "recursion"),
 ("admit-ok-11", '{"a":"\\ud83d\\ude00"}', "valid escaped surrogate pair in a value"),
 ("admit-ok-12", '{"\\ud83d\\ude00":1}', "valid escaped surrogate pair in a name"),
 ("admit-ok-13", ' \t\r\n{"a":1}', "leading JSON whitespace admissible"),
 ("admit-ok-14", '1', "top-level integer admitted"),
 ("admit-ok-15", '"x"', "top-level string admitted"),
 ("admit-ok-16", '[1,true,null]', "top-level array admitted"),
]: add(vid, A, S, N, "accept", src, note)

# ---- admissibility: reject -------------------------------------------------
for vid, src, note in [
 ("admit-fail-num-01", '{"n":1.5}', "non-integer token"),
 ("admit-fail-num-02", '{"n":1.0}', "non-integer TOKEN; a value rule would admit"),
 ("admit-fail-num-03", '{"n":1e0}', "non-integer TOKEN; a value rule would admit"),
 ("admit-fail-num-04", '{"n":1.00}', "non-integer token"),
 ("admit-fail-num-05", '{"n":10e-1}', "non-integer token"),
 ("admit-fail-num-06", '{"n":1E2}', "non-integer token"),
 ("admit-fail-num-07", '{"n":1e30}', "integral-float bypass"),
 ("admit-fail-rng-01", '{"n":9007199254740992}', "one above upper bound"),
 ("admit-fail-rng-02", '{"n":-9007199254740992}', "one below lower bound"),
 ("admit-fail-json-01", '{"n":01}', "leading zero; E_JSON or E_NUM_TOKEN, see spec 4"),
 ("admit-fail-json-02", '{"n":+1}', "leading plus; E_JSON or E_NUM_TOKEN, see spec 4"),
 ("admit-fail-json-03", '{"a":1,', "malformed"),
 ("admit-fail-str-01", '{"a":1,"a":2}', "duplicate member name"),
 ("admit-fail-str-02", '{"a":1,"\\u0061":2}', "duplicate AFTER escape decode"),
 ("admit-fail-str-02b", '{"x":{"a":1,"\\u0061":2}}', "nested duplicate after escape decode"),
 ("admit-fail-str-03", '{"a":1}{}', "trailing content"),
 ("admit-fail-str-04", '{"a":1}x', "trailing content"),
 ("admit-fail-str-07", '{"a":"\\ud800"}', "escaped lone surrogate in a value"),
 ("admit-fail-str-08", '{"\\ud800":1}', "escaped lone surrogate in a name"),
 ("admit-fail-str-09", '{"a":["x","\\udc00"]}', "escaped lone surrogate nested in array"),
 ("admit-fail-str-10", '{"n":NaN}', "non-standard constant"),
 ("admit-fail-str-11", '{"n":Infinity}', "non-standard constant"),
 ("admit-fail-str-12", '{"n":-Infinity}', "non-standard constant"),
]: add(vid, A, S, N, "reject", src, note)

add("admit-fail-str-05", A, S, N, "reject", None, "leading byte-order mark",
    hexin="efbbbf7b2261223a317d")
add("admit-fail-str-06", A, S, N, "reject", None, "raw lone surrogate bytes",
    hexin="7b2261223a22eda08022 7d".replace(" ", ""))

# ---- ruleset_profile -------------------------------------------------------
for vid, src, note in [
 ("kat-01", '{"b":2,"a":1}', "member sort, baseline"),
 ("kat-02", '{"Cafe\u0301":1}', "NFD member name; digest equals kat-03"),
 ("kat-03", '{"Caf\u00e9":1}', "NFC member name; digest equals kat-02"),
 ("kat-04", '{"k":"Cafe\u0301"}', "NFD string VALUE; digest equals kat-04b"),
 ("kat-04b", '{"k":"Caf\u00e9"}', "NFC string value; digest equals kat-04"),
 ("kat-05", '{"cafe\u0301":1,"caff":2}',
  "NFC BEFORE sort. NFD cafe+U0301 sorts before caff; NFC cafe sorts after. "
  "Canonical must be {\"caff\":2,\"cafe\":1} with the composed form second."),
 ("kat-08", '{"a":null,"b":[],"c":{},"d":""}', "retention of null, [], {}, empty string"),
 ("kat-10", '{"o":{"z":0,"a":[true,null,"x"]}}', "recursion, nested sort"),
 ("kat-11", '{"n":-0}', "negative zero canonicalizes to 0; same digest as {\"n\":0}"),
 ("kat-12", '{"n":0}', "pairs with kat-11"),
]: add(f"uor-jcs-nfc-{vid}", RP, S, N, "accept", src, note)

# The named KAT remains admission-scoped; it does not acquire a digest merely
# because it also appears in the registry table.
add("uor-jcs-nfc-kat-09", A, S, N, "accept", '{"n":9007199254740991}',
    "safe-integer boundary admitted")

add("uor-jcs-nfc-fail-03", RP, S, N, "reject",
    '{"A\\u030A":1,"\\u00C5":2}',
    "post-NFC member-name collision is refused, never merged")

# ---- leaf_function ---------------------------------------------------------
add("uor-jcs-nfc-kat-06", LF, "cross_implementation", N, "accept",
    '{"\\ud83d\\ude00":1,"\\uff00":2}',
    "UTF-16 code-unit order, not code point. Orders disagree above the BMP: "
    "D83D < FF00 but 0x1F600 > 0xFF00. Gate 2 converts this to observed.")
add("uor-jcs-nfc-kat-07", LF, "cross_implementation", N, "accept",
    '{"k":"a\\tb\\nc\\u001bd"}',
    "escapes: named two-char where applicable, lowercase \\u001b otherwise. "
    "Gate 2 converts this to observed.")
add("uor-jcs-nfc-kat-13", LF, "cross_implementation", N, "accept",
    '{"k":"caf\\u00e9 \\u00e5"}',
    "non-ASCII emitted raw UTF-8, never \\uXXXX. Gate 2 converts this to observed.")

# ---- leaf_function: ECMAScript formatting, unreachable and non-normative --
for vid, source, spelling, note in [
 ("ecma-number-01", "1e-7", "1e-7", "single-digit negative exponent"),
 ("ecma-number-02", "1.5e-9", "1.5e-9", "observed Python-repr regression"),
 ("ecma-number-03", "1e21", "1e+21", "ECMAScript exponent threshold"),
]:
    V.append({
      "id": vid, "layer": LF, "evidence_mode": S, "normative": False,
      "kind": "leaf_oracle", "input_ieee754_binary64_source": source,
      "asserts": note,
      "expected_output": spelling,
      "scope": "unreachable_under_integer_only_admission",
    })

# ---- contrast: what jcs / the withdrawn jcs-n do with the same input -------
# The uor-jcs-nfc side is computed here by the reference implementation, like every
# other row. The external side is TRANSCRIBED from two separately named external
# sources, never
# computed here: generating a contrast value from our own reference implementation
# would defeat the purpose of a contrast vector.
#
# Digest representation differs by source and is recorded as supplied. Both external
# sources emit bare lowercase hex; uor-jcs-nfc emits `sha256:` + hex (SPEC.md 5).
# The underlying values are equal; only the representation differs. This is the
# representation hazard the drift catalogue records as class 6.

CONTRAST_SOURCES = [
 {"id": "cpb-reference-library",
  "attributed_to": "Steven Mih, Action State Group",
  "implementation": "CPB reference library, scitt-payload-binding @ commit c5e0435",
  "runtime": "CPython 3.10, standard library hashlib",
  "digest_representation": "bare lowercase hex"},
 {"id": "sokolov-local",
  "attributed_to": "Anton Sokolov, Tyche Institute",
  "implementation": "local implementations of jcs and the withdrawn jcs-n",
  "runtime": "CPython 3.12.3, unicodedata 15.0.0",
  "digest_representation": "bare lowercase hex"},
]

CONTRAST_INPUTS = [
 {"label": "NFD", "input_json": '{"Cafe\u0301":1}',
  "preimage_hex": "7b2243616665cc81223a317d",
  "observed": {
    "cpb-reference-library": "a32345db8c15f66e0e7575448a6152db81ac2a6f5d4b6952505cbe5d57af9dc1",
    "sokolov-local":         "a32345db8c15f66e0e7575448a6152db81ac2a6f5d4b6952505cbe5d57af9dc1"}},
 {"label": "NFC", "input_json": '{"Caf\u00e9":1}',
  "preimage_hex": "7b22436166c3a9223a317d",
  "observed": {
    "cpb-reference-library": "8e11dc346f1baa43c60bd58c82600158e0158ef5fccb16215b764931eb6a8914",
    "sokolov-local":         "8e11dc346f1baa43c60bd58c82600158e0158ef5fccb16215b764931eb6a8914"}},
]

contrast_records = []
_inputs_out = []
_ours = set()
for item in CONTRAST_INPUTS:
    raw = item["input_json"].encode("utf-8")
    # cross-check: the transcribed preimage must equal the bytes we were handed
    if raw.hex() != item["preimage_hex"]:
        raise SystemExit(f"contrast preimage mismatch for {item['label']}: "
                         f"{raw.hex()} != {item['preimage_hex']}")
    canon = canonicalize(admit(raw))
    d = digest(canon)
    _ours.add(d)
    _inputs_out.append({
        "label": item["label"],
        "input_json": item["input_json"],
        "input_preimage_hex": item["preimage_hex"],
        "uor_jcs_nfc_canonical_json": canon,
        "uor_jcs_nfc_canonical_preimage_hex": canon.encode("utf-8").hex(),
        "uor_jcs_nfc_digest": d,
        "observed_external": item["observed"],
    })

# ---- contrast validation ---------------------------------------------------
# A transcribed value has no generator to catch a typo, so every structural
# property the record claims is asserted here. Generation aborts on any failure.

def _bad(msg):
    raise SystemExit(f"contrast-nfc-01: {msg}")

_declared = [src["id"] for src in CONTRAST_SOURCES]
if len(set(_declared)) != len(_declared):
    _bad(f"duplicate source id in {_declared}")

_HEX = set("0123456789abcdef")
for item in CONTRAST_INPUTS:
    obs = item["observed"]
    # observation keys exactly match declared source ids -- no extras, none missing
    if set(obs) != set(_declared):
        _bad(f"{item['label']}: observation keys {sorted(obs)} "
             f"!= declared sources {sorted(_declared)}")
    for sid, d in obs.items():
        # exactly 64 lowercase hexadecimal characters, bare (no sha256: prefix)
        if len(d) != 64 or not set(d) <= _HEX:
            _bad(f"{item['label']}/{sid}: digest is not 64 lowercase hex chars: {d!r}")
    # all sources agree for this input
    if len(set(obs.values())) != 1:
        _bad(f"{item['label']}: sources disagree: {obs}")

# every declared source supplies every input
for sid in _declared:
    missing = [i["label"] for i in CONTRAST_INPUTS if sid not in i["observed"]]
    if missing:
        _bad(f"source {sid} did not supply {missing}")

# each source distinguishes NFD from NFC -- checked per source, not globally, so a
# source that returned one value for both inputs cannot hide behind another that did not
for sid in _declared:
    per_source = {i["label"]: i["observed"][sid] for i in CONTRAST_INPUTS}
    if len(set(per_source.values())) != len(per_source):
        _bad(f"source {sid} did not distinguish the inputs: {per_source}")

# uor-jcs-nfc collapses the pair -- the other direction of the discriminator
if len(_ours) != 1:
    _bad(f"uor-jcs-nfc did not collapse the pair: {sorted(_ours)}")

# and the collapsed digest must equal the NFC observation, not some third value
_nfc_observed = {i["observed"][_declared[0]] for i in CONTRAST_INPUTS
                 if i["label"] == "NFC"}
if {d.removeprefix("sha256:") for d in _ours} != _nfc_observed:
    _bad(f"uor-jcs-nfc digest {_ours} does not equal the observed NFC digest "
         f"{_nfc_observed}")

contrast_records.append({
  "id": "contrast-nfc-01",
  "status": "observed",
  "asserts": (
    "Gate A discriminator, two-directional. The decomposed and precomposed inputs "
    "collapse to one digest under uor-jcs-nfc and remain two distinct digests under "
    "jcs and the withdrawn jcs-n, neither of which applies normalization."),
  "inputs": _inputs_out,
  "sources": CONTRAST_SOURCES,
  "evidence_note": (
    "External values are transcribed from the sources named above, not computed by "
    "uor_jcs_nfc_ref.py. Both sources agree on every overlapping value. Organizational "
    "independence of the two sources is not asserted here."),
})

errs = [v for v in V if "ERROR" in v]
out = {
  "schema": "uor-vectors-v1",
  "vector_set": "uor-jcs-nfc-v0.1-rc5",
  "digest_context": "uor-jcs-nfc",
  "generated_by": "uor_jcs_nfc_ref.py, written from SPEC.md 1.1",
  "provenance": [
    "Expected values are generated by a reference implementation written from the "
    "specification, NOT derived from nest_uor/canon.py. The vectors are the oracle; "
    "implementations conform to them.",
    "The three cross_implementation vectors (kat-06, kat-07, kat-13) remain SPECIFIED, "
    "NOT OBSERVED. They are RFC 8785 obligations this profile inherits without "
    "restating, and require a run against an independent JCS implementation.",
    "The contrast record is separate from those three and IS observed: its external "
    "values are transcribed from two named sources and were not computed here. Filling "
    "it does not advance any cross_implementation row.",
    "Canonical strings are shown as Unicode text and hashed as UTF-8 octets.",
    "Address wrapper syntax is out of scope for this digest context; vectors pin the "
    "digest representation only (SPEC.md 5)."
  ],
  "normative_digest_context": {
    "specification": "SPEC.md 1.1",
    "unicode_database": "15.0.0",
    "unicode_version_status": "pinned_normative",
    "unicode_version_note": (
      "SPEC.md 1.3 pins Unicode 15.0.0. NFC behaviour depends on the Unicode version; "
      "an implementation using a different version implements a different digest "
      "context. Generation aborts if the generating runtime does not match."
    ),
    "hash": "SHA-256",
    "digest_representation": "sha256: + 64 lowercase hexadecimal characters"
  },
  "counts": {"total": len(V),
             "admissibility": sum(1 for v in V if v["layer"] == "admissibility"),
             "ruleset_profile": sum(1 for v in V if v["layer"] == "ruleset_profile"),
             "leaf_function": sum(1 for v in V if v["layer"] == "leaf_function"),
             "accept": sum(1 for v in V if v["kind"] == "accept"),
             "reject": sum(1 for v in V if v["kind"] == "reject")},
  "vectors": V,
  "contrast": contrast_records,
}
CONF = Path(__file__).resolve().parent / "conformance"
CONF.mkdir(exist_ok=True)
# Write directly into conformance/ so there is no manual move between generation
# and packaging. A move step is where a record and its corpus drift apart.
corpus_path = CONF / "uor-jcs-nfc-vectors-v0.1-rc5.json"
with corpus_path.open("w", encoding="utf-8") as f:
    json.dump(out, f, indent=2, ensure_ascii=False)
    f.write("\n")

corpus_sha256 = hashlib.sha256(corpus_path.read_bytes()).hexdigest()
here = Path(__file__).resolve().parent
receipt = {
  "schema": "uor-generation-receipt-v1",
  "corpus_file": corpus_path.name,
  "corpus_sha256": corpus_sha256,
  "generator_file": Path(__file__).name,
  "generator_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
  "reference_file": "uor_jcs_nfc_ref.py",
  "reference_sha256": hashlib.sha256((here / "uor_jcs_nfc_ref.py").read_bytes()).hexdigest(),
  "runtime": {
    "python": platform.python_version(),
    "platform": platform.platform(),
    "unicode_database": unicodedata.unidata_version,
  },
  "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
}
with open(CONF / "uor-jcs-nfc-generation-receipt-rc5.json", "w", encoding="utf-8") as f:
    json.dump(receipt, f, indent=2, ensure_ascii=False)
    f.write("\n")
print(f"{len(V)} vectors, {len(errs)} generation errors")
for e in errs: print("  ERROR", e["id"], e["ERROR"])
print(json.dumps(out["counts"], indent=2))
print("corpus sha256", corpus_sha256)
