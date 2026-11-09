"""Shared parallel grading for the pilot scripts.

verifier.grade() resets and reuses one grade worktree per instance,
so completions for the same instance must be graded sequentially,
while different instances are independent. grade_many() groups by
instance and runs the groups in a spawn process pool (spawn, so pool
workers are fresh interpreters that import only this module and src;
safe to call from a process that holds a CUDA model).

A grade that raises (snapshot or test-infra failure) is returned as
an explicit error record with reward 0.0 and taxonomy "grade-error";
it is never silently counted as a blocked exploit or a pass.
"""
from __future__ import annotations

import multiprocessing
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _grade_group(task):
    iid, diffs = task
    from src import snapshots, verifier
    inst = snapshots.load_instance(iid)
    inst["instance_id"] = iid
    out = []
    for d in diffs:
        try:
            rec = verifier.grade(inst, d)
            if "taxonomy" not in rec:
                # The frozen verifier's patch_does_not_apply early
                # return omits the taxonomy field its other returns
                # carry; both pilot consumers index it. Normalise
                # here, pilot-side, with the verifier's own
                # classifier (the verifier itself is not modified).
                rec["taxonomy"] = verifier.classify_taxonomy(rec, d)
            # The tamper early return likewise leaves components
            # empty; it scores nothing, so zero-fill is exact.
            comp = rec.get("components") or {}
            rec["components"] = {
                k: float(comp.get(k, 0.0)) for k in
                ("poc", "mutants", "regression", "minimality")}
            out.append(rec)
        except Exception as e:  # surfaced as an explicit error record
            out.append({"instance": iid, "reward": 0.0, "passed": False,
                        "tamper": False, "flags": ["grade_error"],
                        "components": {"poc": 0.0, "mutants": 0.0,
                                       "regression": 0.0,
                                       "minimality": 0.0},
                        "taxonomy": "grade-error",
                        "error": f"{type(e).__name__}: {e}"[:500]})
    return out


def grade_many(items: list[dict], workers: int = 4) -> list[dict]:
    """items: [{instance_id, diff, ...}] -> verifier records in the
    same order as items."""
    groups: dict[str, list[int]] = {}
    for idx, it in enumerate(items):
        groups.setdefault(it["instance_id"], []).append(idx)
    tasks = [(iid, [items[i]["diff"] for i in idxs], idxs)
             for iid, idxs in groups.items()]
    results: list[dict | None] = [None] * len(items)
    if workers <= 1 or len(tasks) <= 1:
        for iid, diffs, idxs in tasks:
            for i, r in zip(idxs, _grade_group((iid, diffs))):
                results[i] = r
        return results  # type: ignore[return-value]
    ctx = multiprocessing.get_context("spawn")
    with ProcessPoolExecutor(max_workers=min(workers, len(tasks)),
                             mp_context=ctx) as ex:
        futs = {ex.submit(_grade_group, (iid, diffs)): idxs
                for iid, diffs, idxs in tasks}
        for fut in as_completed(futs):
            for i, r in zip(futs[fut], fut.result()):
                results[i] = r
    return results  # type: ignore[return-value]
