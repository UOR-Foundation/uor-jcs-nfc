# uor-jcs-nfc

> **Publication status — provisional RC5 draft.** `SPEC.md` version 1.1 and
> `uor_jcs_nfc_ref.py` are the stable publication targets in this commit. The
> aggregate corpus in `conformance/` is retained as author-side RC5 history; it
> is not the canonical registry corpus. Its observed contrast record is a
> breaking shape change and therefore requires regeneration as
> `uor-vectors-v2`. Whether that regeneration also includes CPB per-file
> vectors remains pending. A registry entry must cite the later final commit,
> not this provisional corpus.

A JSON digest context: raw UTF-8 bytes to `sha256:<hex>`, with admission,
canonicalization, hash, and representation all pinned together.

RFC 8785 (JCS) with four additions — lexical admission of integer number tokens only,
Unicode NFC applied before member sort, refusal of post-normalization member-name
collisions, and a pinned digest representation. See [`SPEC.md`](SPEC.md), which is
self-contained: everything needed to implement this context and reproduce the corpus is
in it.

## Contents

| Path | |
|---|---|
| `SPEC.md` | Normative specification, version 1.1 |
| `uor_jcs_nfc_ref.py` | Reference implementation, written from the spec |
| `gen_vectors.py` | Corpus generator |
| `conformance/` | Vector corpus, generation receipt, mutation suite and report |

## Conformance

```bash
cd conformance
PYTHONPATH=.. python3 run_mutants.py uor-jcs-nfc-vectors-v0.1-rc5.json
```

Expected: baseline 56 passed, 3 skipped, 0 failed; then 21 mutants — 18 exact, 3
survived, 0 divergent, 0 unexercised.

The three skipped rows are `leaf_oracle` vectors, which assert a number-formatter output
rather than a digest. They are not replayable through `admit`/`canonicalize` and are
deliberately not counted as passes.

`PYTHONPATH=..` is required because the mutation suite imports the reference
implementation from the parent directory.

## Regenerating the corpus

```bash
python3 gen_vectors.py
```

**Requires a runtime using Unicode 15.0.0, such as CPython 3.12.x.** Refusal under a
different Unicode database is expected and protects the pinned digest context — NFC
behaviour depends on the Unicode version, and a corpus generated under a different one
describes a different context. CPython 3.13 ships Unicode 15.1.0 and will be refused.

The corpus regenerates byte-identically on any conforming runtime. The generator writes the
corpus and receipt into `conformance/` directly, so there is no move step between generation
and packaging. Runtime metadata lives in the generation receipt rather than the corpus, so
the corpus digest is stable across environments:

```
conformance/uor-jcs-nfc-vectors-v0.1-rc5.json
63b2bc42f69058731475372f3d1a97fc01862692c6900a036861a155c0e95e1b
```

## Design notes

Expected values come from the reference implementation, written from the specification —
not derived from any pre-existing implementation. **The vectors are the oracle**;
implementations conform to them, rather than an implementation's behaviour becoming the
definition.

Every vector declares `layer`, `evidence_mode`, and `normative` as three orthogonal axes.
Rows marked `evidence_mode: cross_implementation` are specified but carry no external
evidence yet; they cover RFC 8785 obligations this profile inherits without restating.

The mutation suite exists because a check that cannot fail is not a check. Each mutant
removes exactly one condition; the corpus must then fail, with the predicted vectors
failing. Three mutants survive by design and are recorded rather than dropped — one
equivalent mutant, one that identified unreachable defensive code in the reference
implementation, and a round-trip no-op that no corpus vector can catch.

## `jcs1` is a different context

Some existing UOR code implements a ruleset named `jcs1`, rendering addresses as
`uor:jcs1-sha256:…`. It admits floating-point values and differs in representation and
empty-member handling. `jcs1` addresses **must not** be relabelled as `uor-jcs-nfc` — a
`jcs1` address over a document containing `1.0` has no equivalent here, because that
document is inadmissible. See `SPEC.md` §1.4.

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
