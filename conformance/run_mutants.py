#!/usr/bin/env python3
"""
run_mutants.py — replay the vector corpus against each condition-removed mutant.

A mutant that no vector catches is an unexercised check family. A mutant caught by
vectors other than the ones predicted is a mis-attributed check.

    python run_mutants.py uor-jcs-nfc-vectors-v0.1-rc5.json
    python run_mutants.py uor-jcs-nfc-vectors-v0.1-rc5.json --json report.json
"""

import argparse, copy, hashlib, importlib, json, sys, unicodedata

import uor_jcs_nfc_ref as ref
import mutants

PINNED_UNICODE = "15.0.0"          # SPEC.md 1.3, normative
if unicodedata.unidata_version != PINNED_UNICODE:
    raise SystemExit(
        f"refusing to run: runtime Unicode {unicodedata.unidata_version} != pinned "
        f"{PINNED_UNICODE} (SPEC.md 1.3). Replaying the corpus under a different "
        f"Unicode version exercises a different digest context, so the resulting "
        f"catch sets would not describe this corpus."
    )

# Snapshot every mutable attribute so mutants can be undone exactly.
_SNAPSHOT = {n: getattr(ref, n) for n in dir(ref) if not n.startswith("__")}


def restore():
    for n, v in _SNAPSHOT.items():
        setattr(ref, n, v)
    for n in [x for x in dir(ref) if not x.startswith("__") and x not in _SNAPSHOT]:
        delattr(ref, n)


def replay(vec):
    """Run one vector. Returns (ok, observed) — ok means it matches expectations."""
    if vec.get("kind") == "leaf_oracle":
        return None, "leaf_oracle (not replayable via admit/canonicalize)"
    raw = (bytes.fromhex(vec["input_hex"]) if "input_hex" in vec
           else vec["input_json"].encode("utf-8"))
    try:
        value = ref.admit(raw)
    except ref.Refused as e:
        if vec["expected_result"] == "REFUSED":
            # E_JSON / E_NUM_TOKEN are interchangeable for json-01/-02 per spec §4
            exp = vec["expected_code"]
            alt = {"E_JSON", "E_NUM_TOKEN"}
            ok = e.code == exp or (exp in alt and e.code in alt
                                   and vec["id"].startswith("admit-fail-json"))
            return ok, e.code
        return False, f"REFUSED {e.code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"

    if vec["expected_result"] == "ADMITTED":
        return True, "ADMITTED"

    # A ruleset_profile reject (e.g. post-NFC collision) is admitted, then
    # refused during canonicalization. Admission succeeding is not yet a failure.
    try:
        canon = ref.canonicalize(value)
    except ref.Refused as e:
        if vec["expected_result"] == "REFUSED":
            return e.code == vec["expected_code"], e.code
        return False, f"REFUSED {e.code}"
    except Exception as e:
        # A crash is a failure to produce the expected digest, which counts as
        # caught. Mutants that break encoding rather than change it land here.
        return False, f"CRASH {type(e).__name__}"

    if vec["expected_result"] == "REFUSED":
        return False, "ADMITTED and canonicalized"
    d = ref.digest(canon)
    return d == vec["expected_digest"], d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--json")
    a = ap.parse_args()

    J = json.load(open(a.corpus))
    vectors = J["vectors"]
    corpus_sha = hashlib.sha256(open(a.corpus, "rb").read()).hexdigest()

    # baseline: the unmutated reference must pass everything
    base = [(v["id"], replay(v)[0]) for v in vectors]
    base_fail = [i for i, ok in base if ok is False]
    base_skip = [i for i, ok in base if ok is None]
    base_pass = [i for i, ok in base if ok is True]
    print(f"corpus   {a.corpus}")
    print(f"sha256   {corpus_sha}")
    print(f"baseline {len(base_pass)} passed, {len(base_skip)} skipped, "
          f"{len(base_fail)} failed  (of {len(vectors)})")
    if base_skip:
        print(f"         skipped: {', '.join(base_skip)}")
        print(f"         leaf_oracle rows assert a formatter output, not a digest. "
              f"They are not replayable through admit/canonicalize and are NOT "
              f"counted as passes.")
    if base_fail:
        print(f"         FAILURES: {', '.join(base_fail)}")
    if base_fail:
        print("\nBaseline must be clean before mutants mean anything.")
        return 2
    print()

    results, unexercised, divergent = [], [], []
    for mid, apply_fn, predicted, note in mutants.MUTANTS:
        restore()
        apply_fn()
        caught = [v["id"] for v in vectors if replay(v)[0] is False]
        restore()

        expected_survivor = not predicted   # empty prediction == documented survivor
        pred, got = set(predicted), set(caught)
        missed = sorted(pred - got)          # predicted but did not fire
        extra  = sorted(got - pred)          # fired but not predicted
        exact  = (pred == got)

        status = ("SURVIVED" if not caught else
                  "EXACT" if exact else "DIVERGENT")

        if not caught and not expected_survivor:
            unexercised.append(mid)
        if missed or extra:
            divergent.append((mid, missed, extra))

        ok = expected_survivor or exact
        print(f"  {'OK ' if ok else '!! '}{mid:<38} {status:<10} {len(caught):>2} caught")
        if note:
            print(f"       {note}")
        if missed:
            print(f"       PREDICTED, NOT CAUGHT: {missed}")
        if extra:
            print(f"       CAUGHT, NOT PREDICTED: {extra}")
        results.append({"id": mid, "status": status, "predicted": predicted,
                        "caught": caught, "predicted_not_caught": missed,
                        "caught_not_predicted": extra, "note": note})

    print()
    print(f"  {len(results)} mutants | "
          f"{sum(1 for r in results if r['status']=='EXACT')} exact | "
          f"{sum(1 for r in results if r['status']=='SURVIVED')} survived | "
          f"{len(unexercised)} unexercised | {len(divergent)} divergent")
    if unexercised:
        print(f"\n  UNEXERCISED — no vector catches these; the check family is not tested:")
        for m in unexercised:
            print(f"    {m}")
    if divergent:
        print(f"\n  DIVERGENT — prediction and outcome differ:")
        for m, missed, extra in divergent:
            print(f"    {m}")
            if missed: print(f"      predicted, not caught: {missed}")
            if extra:  print(f"      caught, not predicted: {extra}")

    if a.json:
        json.dump({"report_revision": 2,
                   "correction": "Exact predicted-versus-observed catch-set "
                                 "comparison; leaf_oracle rows reported as skipped "
                                 "rather than counted as baseline passes; MUT-12 "
                                 "reduced to a single removed condition",
                   # Defined field: the runner reads the corpus and never writes
                   # it. Asserted per run against the digest recorded above, so it
                   # is a property of THIS run, not a claim about release history.
                   "corpus_unmodified_by_this_run": corpus_sha == hashlib.sha256(
                       open(a.corpus, "rb").read()).hexdigest(),
                   "runtime_unicode_database": unicodedata.unidata_version,
                   "corpus_file": a.corpus, "corpus_sha256": corpus_sha,
                   "baseline": {"passed": len(base_pass),
                                "skipped": len(base_skip),
                                "skipped_ids": base_skip,
                                "failed": len(base_fail),
                                "total": len(vectors),
                                "skip_reason": (
                                  "leaf_oracle rows assert a formatter output rather "
                                  "than a digest; they are not replayable through "
                                  "admit/canonicalize and are not counted as passes")},
                   "mutants": results,
                   "unexercised": unexercised,
                   "divergent": [{"id": m, "predicted_not_caught": p,
                                  "caught_not_predicted": c}
                                 for m, p, c in divergent]},
                  open(a.json, "w"), indent=2)
        print(f"\n  -> {a.json}")

    return 1 if (unexercised or divergent) else 0


if __name__ == "__main__":
    sys.exit(main())
