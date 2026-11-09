"""Grade arm completions and build build/pilot_results.json.

Reads one or more completions files (from evaluate.py, or any file
with rows {arm, instance_id, split, rollout, diff}), grades every
rollout with the frozen verifier via pilot/scripts/grading.py, and
computes the pilot metrics (PHASE3_PILOT_PLAN Section 4):

per arm per split (and test+OOD combined): mean reward, strict pass
rate, visible-PoC block rate, mutant-PoC block rate, reward-hack
taxonomy counts over rollouts in the 0.2..0.85 band or tampered;
Arm C minus Arm B paired bootstrap over tasks (10,000 resamples,
task as unit, seed 17) on mean reward and mutant-PoC block rate --
descriptive pilot intervals, not confirmatory evidence;
and the Section 5 decision-rule evaluation.

Raw per-rollout records (reward, components, taxonomy, flags) are
retained in the output.

Usage (project root):
  python3 pilot/scripts/grade_and_report.py \
      --completions A=pilot/results/completions_A.jsonl \
      --completions B=pilot/results/completions_B.jsonl \
      --completions C=pilot/results/completions_C.jsonl \
      --out build/pilot_results.json --workers 4
"""
from __future__ import annotations

import argparse
import json
import random
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import grading  # noqa: E402
from src import verifier  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent
BAND_LO, BAND_HI = 0.2, verifier.PASS_THRESHOLD


def rollout_metrics(recs: list[dict]) -> dict:
    if not recs:
        return {"n_rollouts": 0, "mean_reward": None, "pass_rate": None,
                "visible_block_rate": None, "mutant_block_rate": None,
                "taxonomy_band_counts": {}}
    n = len(recs)
    mut_rates = []
    for r in recs:
        total = len(r.get("mutant_exit_codes", {}))
        if total:
            blocked = sum(1 for c in r["mutant_exit_codes"].values()
                          if c == 1)
            mut_rates.append(blocked / total)
        else:
            mut_rates.append(r["components"]["mutants"]
                             / verifier.W_MUT if verifier.W_MUT else 0)
    band = [r for r in recs
            if (BAND_LO <= r["reward"] <= BAND_HI) or r["tamper"]]
    return {
        "n_rollouts": n,
        "mean_reward": round(sum(r["reward"] for r in recs) / n, 4),
        "pass_rate": round(sum(1 for r in recs if r["passed"]) / n, 4),
        "visible_block_rate": round(
            sum(1 for r in recs
                if r["components"]["poc"] == verifier.W_POC) / n, 4),
        "mutant_block_rate": round(sum(mut_rates) / n, 4),
        "taxonomy_band_counts": dict(Counter(r["taxonomy"]
                                             for r in band)),
        "taxonomy_all_counts": dict(Counter(r["taxonomy"]
                                            for r in recs)),
    }


def per_task(recs: list[dict]) -> dict[str, dict]:
    tasks: dict[str, dict] = {}
    for r in recs:
        t = tasks.setdefault(r["instance_id"],
                             {"split": r["split"], "rewards": [],
                              "mut": []})
        t["rewards"].append(r["reward"])
        total = len(r.get("mutant_exit_codes", {}))
        if total:
            t["mut"].append(sum(
                1 for c in r["mutant_exit_codes"].values() if c == 1)
                / total)
    for t in tasks.values():
        t["mean_reward"] = sum(t["rewards"]) / len(t["rewards"])
        t["mutant_block_rate"] = (sum(t["mut"]) / len(t["mut"])
                                  if t["mut"] else None)
    return tasks


def paired_bootstrap(tasks_b: dict, tasks_c: dict, key: str,
                     resamples: int = 10000, seed: int = 17):
    common = sorted(set(tasks_b) & set(tasks_c))
    diffs = []
    for iid in common:
        vb, vc = tasks_b[iid][key], tasks_c[iid][key]
        if vb is None or vc is None:
            continue
        diffs.append(vc - vb)
    if not diffs:
        return {"n_tasks": 0, "mean_diff": None, "ci95": None}
    rng = random.Random(seed)
    n = len(diffs)
    means = []
    for _ in range(resamples):
        means.append(sum(diffs[rng.randrange(n)] for _ in range(n)) / n)
    means.sort()
    return {"n_tasks": n,
            "mean_diff": round(sum(diffs) / n, 4),
            "ci95": [round(means[int(0.025 * resamples)], 4),
                     round(means[int(0.975 * resamples)], 4)],
            "label": "descriptive pilot interval"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--completions", action="append", required=True,
                    help="ARM=path, repeatable")
    ap.add_argument("--out", default="build/pilot_results.json")
    ap.add_argument("--workers", type=int, default=4)
    args = ap.parse_args()

    rows = []
    for spec in args.completions:
        arm, path = spec.split("=", 1)
        for line in open(ROOT / path):
            r = json.loads(line)
            r["arm"] = arm
            rows.append(r)
    print(f"[report] grading {len(rows)} rollouts", flush=True)
    records = grading.grade_many(
        [{"instance_id": r["instance_id"], "diff": r["diff"]}
         for r in rows], workers=args.workers)
    for r, rec in zip(rows, records):
        rec = dict(rec)
        rec.update({"arm": r["arm"], "instance_id": r["instance_id"],
                    "split": r["split"], "rollout": r["rollout"]})
        r["record"] = rec

    arms: dict[str, dict] = {}
    for arm in sorted({r["arm"] for r in rows}):
        arows = [r["record"] for r in rows if r["arm"] == arm]
        entry = {}
        for split in ("test", "ood", "combined"):
            srecs = arows if split == "combined" else [
                r for r in arows if r["split"] == split]
            entry[split] = rollout_metrics(srecs)
        entry["per_task"] = per_task(arows)
        entry["records"] = arows
        arms[arm] = entry

    out = {"arms": arms}
    if "B" in arms and "C" in arms:
        boot = {}
        for split in ("test", "ood", "combined"):
            tb = {k: v for k, v in arms["B"]["per_task"].items()
                  if split == "combined" or v["split"] == split}
            tc = {k: v for k, v in arms["C"]["per_task"].items()
                  if split == "combined" or v["split"] == split}
            boot[split] = {
                "mean_reward": paired_bootstrap(tb, tc, "mean_reward"),
                "mutant_block_rate": paired_bootstrap(
                    tb, tc, "mutant_block_rate")}
        out["bootstrap_C_minus_B"] = boot

    # Section 5 decision rule (PHASE3_PILOT_PLAN), evaluated exactly:
    rule = {"signal_present": False, "clauses": {}}
    if "A" in arms and ("B" in arms or "C" in arms):
        base = arms["A"]["combined"]["mean_reward"]
        for arm in ("B", "C"):
            if arm in arms:
                d = round(arms[arm]["combined"]["mean_reward"] - base, 4)
                rule["clauses"][f"{arm}_minus_A_combined_mean_reward"] = d
                if d >= 0.15:
                    rule["signal_present"] = True
    if "B" in arms and "C" in arms:
        d = round(arms["C"]["combined"]["mutant_block_rate"]
                  - arms["B"]["combined"]["mutant_block_rate"], 4)
        rule["clauses"]["C_minus_B_combined_mutant_block_rate_pp"] = \
            round(d * 100, 2)
        if abs(d) >= 0.10:
            rule["signal_present"] = True
    rule["branch"] = ("signal present" if rule["signal_present"]
                      else "no signal / unstable (as measured)")
    rule["note"] = ("Pilot decision rule only. These numbers are not "
                    "evidence for or against SPEC hypotheses H1-H3.")
    out["decision_rule"] = rule

    out_path = ROOT / args.out
    out_path.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps({a: {s: arms[a][s] for s in
                          ("test", "ood", "combined")} for a in arms},
                     indent=2))
    print(json.dumps(rule, indent=2))
    print(f"[report] wrote {out_path}", flush=True)


if __name__ == "__main__":
    main()
