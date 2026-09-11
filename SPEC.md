# UOR-JCS-NFC

**Version:** 1.1
**Status:** draft
**License:** Apache-2.0

**Revision note.** Version 1.1 changes §9 only. The contents list is now release-neutral:
release-specific filenames appear as `<release>` templates, and each release's
`MANIFEST.sha256` supplies the exact names and digests. The `LICENSE` file, named in §9 of
version 1.0 but absent from the version 1.0 distribution, is included. **The normative
content of §§1 through 8 is unchanged from version 1.0**, so a digest computed under version
1.0 is identical to one computed under version 1.1; this is a packaging revision, not a
change of digest context.

A digest context: a complete, pinned set of rules that determines the digest of a JSON
document. Admission, canonicalization, hash, and representation are specified together,
because a digest is only reproducible if all four are fixed.

This document is self-contained. Everything required to implement `uor-jcs-nfc` and to
reproduce the conformance corpus is here. No other document is needed.

---

## 1. Scope

`uor-jcs-nfc` maps raw UTF-8 bytes to a digest, in three stages:

```
admit(bytes)          -> value          §3   lexical and structural admission
canonicalize(value)   -> string         §4   NFC, collision refusal, JCS encoding
digest(string)        -> "sha256:<hex>" §5   SHA-256, lowercase hex
```

Each stage is independently testable and independently conformance-checked.

**Out of scope:** address wrapper syntax, resolution, storage, authorization, publisher
identity, and execution evidence. A digest context answers *what bytes hash to what*; it
does not define what a system may conclude from the result.

### 1.1 Requirements language

MUST, MUST NOT, SHOULD, MAY as in BCP 14 (RFC 2119, RFC 8174), when in all capitals.

### 1.2 Relationship to RFC 8785

`uor-jcs-nfc` is RFC 8785 (JCS) with four additions, each stated normatively below:

| Addition | Section |
|---|---|
| Lexical admission — integer number tokens only | §3.5 |
| Unicode NFC over member names and string values, **before** member sort | §4.2 |
| Post-normalization member-name collisions refused, never merged | §4.3 |
| Digest representation pinned to `sha256:` + 64 lowercase hex | §5 |

It relaxes nothing in RFC 8785. Escape rules (§3.2.2.2) and member ordering (§3.2.3) apply
unchanged, and are exercised by the corpus rather than assumed.

### 1.3 Pinned Unicode version

Normalization MUST use **Unicode 15.0.0**. This is normative, not advisory: NFC behavior
depends on the Unicode version, and an implementation using a different version is
implementing a different digest context. The conformance corpus records the same version.

### 1.4 `jcs1` is a different context

Some existing UOR code implements a ruleset named `jcs1`, rendering addresses as
`uor:jcs1-sha256:…`. `jcs1` admits floating-point values and differs in representation and
empty-member handling. It is a **distinct digest context**, not an earlier spelling of this
one.

An existing `jcs1` address over a document containing `1.0` has no `uor-jcs-nfc` equivalent,
because that document is inadmissible here. Implementations MUST NOT relabel `jcs1` addresses
as `uor-jcs-nfc`.

---

## 2. Why admission is a separate stage

A JSON parser destroys the information admission needs. After parsing, `1.0`, `1e0`, `1.00`,
and `10e-1` are one value; `{"a":1,"a":2}` has become `{"a":2}`. A canonicalizer receiving a
parsed structure therefore cannot enforce a lexical rule, however the rule is worded.

Admission consequently operates on **raw bytes**, before parsing, and is specified first.

---

## 3. Admission

```
admit(data: bytes) -> value
```

Input is raw UTF-8 bytes. Implementations MUST NOT expose an equivalent taking a decoded
string, because decoding is itself one of the checks.

Objects are returned with duplicate member names already refused (§3.4). Distinct
pre-normalization names survive unchanged, so §4.3 can detect collisions.

### 3.1 Encoding

Decode UTF-8 strictly. No error fallback, no replacement characters, no `utf-8-sig`.

### 3.2 Byte-order mark

A leading `EF BB BF` MUST be refused. This MUST be a byte-level check before parsing. Some
JSON libraries reject a BOM on string input and silently accept it on byte input.

### 3.3 Trailing content

Parse one top-level value and inspect the remainder. Trailing whitespace is admissible; any
other trailing content MUST be refused.

### 3.4 Duplicate member names

Member names MUST be compared **after JSON escape decoding and before normalization**. So
`{"a":1,"\u0061":2}` is a duplicate and MUST be refused: escape spelling is not a JSON-level
distinction, while normalization equivalence is a separate concern handled in §4.3.

### 3.5 Numbers

Number tokens MUST be validated as **text**, before any numeric conversion.

- A number token MUST match `-?(0|[1-9][0-9]*)`.
- Its value MUST lie within `[-9007199254740991, 9007199254740991]` inclusive.
- Any other number token MUST be refused, **including tokens whose mathematical value is
  integral** — `1.0`, `1e0`, `1.00`, and `10e-1` are all refused.

The rule is lexical. A type test or a value test is **not** a conforming implementation of
it: a value test admits `1.0`, and a type test can admit a floating-point representation of
an integral value that the same guard rejects as an integer. §8 pins this with a mutant.

`-0` matches the grammar and is **admissible**. It canonicalizes to `0` per §4.4, which is
correct JCS behavior — collapsing source-text multiplicity into one canonical form is what
canonicalization is for.

### 3.6 Constants

`NaN`, `Infinity`, `-Infinity`, and any other non-standard constant MUST be refused.

### 3.7 Surrogates

After parsing, scan **recursively over every member name and every string value**.

- Raw surrogate bytes fail strict UTF-8 decoding (§3.1) and are refused there.
- **Escaped** lone surrogates such as `\ud800` are admitted by some JSON parsers and MUST be
  refused explicitly.
- A valid escaped surrogate **pair** such as `\ud83d\ude00` denotes `U+1F600` and is
  admissible.

### 3.8 Error codes

Refusals MUST carry a stable code, not a parser-dependent message.

| Code | Condition |
|---|---|
| `E_BOM` | Leading byte-order mark |
| `E_UTF8` | Not well-formed UTF-8, including raw surrogate bytes |
| `E_JSON` | Malformed JSON |
| `E_TRAILING` | Non-whitespace content after the top-level value |
| `E_NUM_TOKEN` | Number token outside the §3.5 grammar |
| `E_NUM_RANGE` | Integer outside the §3.5 bound |
| `E_CONSTANT` | Non-standard constant |
| `E_DUP_NAME` | Duplicate member name |
| `E_SURROGATE` | Unpaired surrogate reached by escape |

**Codes an implementation cannot produce.** Some parsers reject `01` and `+1` before any
number-token hook is reached, yielding only a generic error. Both are invalid JSON regardless
of profile, so `E_JSON` is conforming for them. An implementation with its own tokenizer MAY
report `E_NUM_TOKEN` instead. The corpus accepts either.

### 3.9 Error precedence

One malformed input MUST receive one code across implementations. Report the first that
applies:

```
E_BOM
  -> E_UTF8
    -> E_JSON / E_NUM_TOKEN / E_NUM_RANGE / E_CONSTANT   (parse-time, positional)
      -> E_TRAILING
        -> E_DUP_NAME
          -> E_SURROGATE
```

Parse-time codes are grouped because they fire in input order rather than rule order.
`E_TRAILING` follows them because the remainder check requires a decoded prefix.
`E_DUP_NAME` and `E_SURROGATE` follow because both are post-parse scans.

### 3.10 Resource limits

Depth and size limits are implementation-defined and outside this specification. Resource
exhaustion is an implementation failure, not a refusal, and has no code.

One requirement: an implementation MUST NOT return a value from a document it did not fully
parse. Partial success is prohibited.

Implementations SHOULD support at least 100 levels of nesting. The corpus does not test
beyond that depth.

---

## 4. Canonicalization

```
canonicalize(value) -> string
```

### 4.1 Order of operations

Normative, in this order:

1. Normalize every member name and every string value to NFC, recursively (§4.2).
2. Refuse post-normalization member-name collisions (§4.3).
3. Sort members and encode per RFC 8785 (§4.5, §4.6).

### 4.2 Normalization before sort

NFC MUST be applied **before** member sort, and to member names **and** string values.

The ordering is normative, not incidental. Normalization changes the code units a sort ranks,
so a name normalized after sorting can occupy a position the sort did not assign it. Two
implementations that both apply NFC still produce different canonical forms if they disagree
about when.

Worked case, pinned as `uor-jcs-nfc-kat-05`. Input:

```json
{"cafe\u0301":1,"caff":2}
```

Decomposed, the first name ends `e` (`U+0065`) and sorts before `caff`. Composed, it ends `é`
(`U+00E9`) and sorts after. Therefore:

- NFC before sort: `{"caff":2,"café":1}`
- NFC after sort: `{"café":1,"caff":2}`

Different canonical forms, different digests, from one input.

### 4.3 Collision refusal

Normalization can map two distinct member names onto one — `A` + `U+030A` and `U+00C5` both
normalize to `Å`. Such an object MUST be refused.

It MUST NOT be resolved by last-write-wins, first-write-wins, or merging. Any of those
silently discards a member the digest claims to identify. A silently shared address for two
different documents is worse than a refused document.

Collision refusal is necessarily part of this stage: a component receiving a structure with
duplicate names already collapsed cannot detect it.

### 4.4 Numbers

Only integers reach this stage (§3.5). Emit the shortest decimal representation with no sign
for zero, no leading zeros, and no exponent. `-0` emits `0`.

### 4.5 Member ordering

Sort by the UTF-16 code units of the **NFC-normalized, unescaped** member name, per RFC 8785
§3.2.3.

Code-unit order and code-point order agree across the entire BMP and diverge above it,
because surrogate pairs order differently than the scalar values they encode. `U+1F600`
precedes `U+FF00` under code-unit order (`D83D` < `FF00`) and follows it under code-point
order. Pinned as `uor-jcs-nfc-kat-06`.

### 4.6 Strings

Per RFC 8785 §3.2.2.2:

- `"` and `\` escaped with a backslash.
- `U+0008`, `U+000C`, `U+000A`, `U+000D`, `U+0009` as `\b`, `\f`, `\n`, `\r`, `\t`.
- Other code points below `U+0020` as `\u00xx`, **lowercase** hex.
- Everything else emitted as raw UTF-8. Non-ASCII MUST NOT be escaped.

### 4.7 Empty and null members

`null`, `[]`, `{}`, and `""` MUST be retained.

Removing them is a semantic transform: it makes *absent* and *present-but-empty*
indistinguishable at the digest layer. Where a producer treats those as different documents,
the canonicalizer must not quotient them first. Some neighboring contexts remove them; this
one does not.

### 4.8 Output

The canonical form is a Unicode string, hashed as its UTF-8 encoding.

---

## 5. Digest and representation

SHA-256 over the UTF-8 encoding of the canonical form, rendered as:

```
sha256:<64 lowercase hexadecimal characters>
```

The `sha256:` prefix is part of the representation. Uppercase hex is non-conforming.
Comparison between two digests MUST compare the algorithm as well as the value.

---

## 6. Conformance

An implementation conforms if it:

1. implements §3, §4, and §5 exactly;
2. uses Unicode 15.0.0 for normalization (§1.3);
3. passes every normative vector in `conformance/`, both accepts and refusals, with matching
   error codes; and
4. is caught by every mutant in `conformance/` that the mutation report predicts.

Conformance is established by passing the vectors, not by assertion. A claim SHOULD cite the
corpus version and its digest.

---

## 7. Conformance corpus

`conformance/` holds a two-sided corpus: positive vectors with pinned canonical forms and
digests, and MUST-FAIL vectors with pinned error codes.

Every vector declares three orthogonal axes:

```json
{
  "layer": "admissibility | semantic_preprocessing | leaf_function | ruleset_profile",
  "evidence_mode": "self | cross_implementation",
  "normative": true
}
```

`layer` says which behavior a vector can establish a claim about. `evidence_mode` says how
the claim was obtained. `normative` says whether passing it establishes conformance. These
vary independently; collapsing any two conflates a claim with its evidence.

Layer boundaries:

| Layer | Test |
|---|---|
| `admissibility` | Could this refuse a document on lexical or structural form, before any transformation? |
| `semantic_preprocessing` | Does this decide which facts exist, rather than how they are encoded? |
| `leaf_function` | Would a conformant RFC 8785 implementation have to do this too? |
| `ruleset_profile` | Is this a choice RFC 8785 does not determine? |

Cross-implementation is **not** a layer. It is an evidence mode applied to a behavior.

Expected values are produced by the reference implementation in this repository, written from
this specification. The vectors are the oracle; implementations conform to them, rather than
an implementation's behavior becoming the definition.

Rows marked `evidence_mode: cross_implementation` are specified but carry no external
evidence yet. They cover RFC 8785 obligations this profile inherits without restating, and
are converted to observed by a run against an independent JCS implementation.

---

## 8. Mutation probes

A check that cannot fail is not a check. The corpus therefore ships condition-removed
mutants: each removes exactly one condition from the reference implementation, and the corpus
must then fail, with the specific vectors named in the mutation report failing.

A mutant no vector catches marks an unexercised check family and MUST be recorded as such
rather than dropped.

Two survivors are recorded deliberately, because a corpus's limits are part of its
description:

- **Equivalent mutants**, behaviorally indistinguishable at every reachable boundary. A
  value-based bound test and a token-based one agree throughout, because binary64 is exact
  through 2^53.
- **Round-trip no-ops.** A function that returns its input passes every idempotence assertion,
  because idempotence on a no-op is trivially true. No vector can catch it; only a mutant can.

The mutant that matters most replaces lexical admission (§3.5) with a value test. It is
caught by five vectors, and it reproduces a defect observed in a shipped implementation where
a type-based guard admitted a floating-point representation of `2^53` while refusing the
integer.

---

## 9. Contents

```
SPEC.md                                        this document
LICENSE                                        Apache-2.0
uor_jcs_nfc_ref.py                             reference implementation
gen_vectors.py                                 corpus generator
conformance/
  uor-jcs-nfc-vectors-<release>.json           the corpus
  uor-jcs-nfc-generation-receipt-<release>.json
                                               corpus digest, generator and runtime provenance
  mutants.py                                   condition-removed mutants
  run_mutants.py                               mutation runner
  mutation-report-<release>.json               run results
```

This list states artifact **roles**. Release-specific filenames are shown as `<release>`
templates; each release's `MANIFEST.sha256` supplies the exact names and digests and is
authoritative. This section therefore does not change from one release candidate to the next.

The corpus regenerates byte-identically from `gen_vectors.py` and the reference
implementation. Runtime metadata is held in the receipt rather than the corpus, so the corpus
digest is stable across environments and can be pinned.

---

## 10. References

**Normative**

- RFC 2119, RFC 8174 — requirements language
- RFC 8259 — JSON
- RFC 8785 — JSON Canonicalization Scheme
- FIPS 180-4 — SHA-256
- Unicode Standard Annex #15, Unicode 15.0.0 — Normalization Forms
