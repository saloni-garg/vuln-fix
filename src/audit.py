"""Audit runner: gold control + degenerate battery per verified
instance (SPEC Sections 5 and 8, gate 1). Used for Phase 1
(build/audit_phase1.json) and Phase 2 (build/audit_phase2.json).

Gate: gold mean reward == 1.0 across verified instances AND zero
battery false passes. If the gate fails, the defect is fixed at the
source and this audit is re-run in full; the run history is kept in
build/audit_runs/ so a re-run does not erase the earlier failure.

Usage: python3 -m src.audit [output_filename]
(default output_filename: audit_phase1.json)
"""
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import battery, snapshots, verifier

ROOT = snapshots.ROOT


def audit_instance(inst: dict) -> dict:
    iid = inst["instance_id"]
    print(f"[audit] {iid}: gold", flush=True)
    gold = verifier.grade(inst, verifier.load_gold_diff(inst))
    items = battery.generate_battery(inst)
    records = []
    false_passes = 0
    for item in items:
        if "transform_error" in item:
            records.append({"item": item["item"], "name": item["name"],
                            "transform_error": item["transform_error"]})
            print(f"[audit] {iid}: battery {item['item']} "
                  f"TRANSFORM ERROR {item['transform_error']}", flush=True)
            continue
        print(f"[audit] {iid}: battery {item['item']} {item['name']}",
              flush=True)
        r = verifier.grade(inst, item["diff"])
        r = {"item": item["item"], "name": item["name"], **r}
        if r["passed"]:
            false_passes += 1
        records.append(r)
    return {"gold": gold, "battery": records,
            "battery_false_passes": false_passes}


def main():
    out_name = sys.argv[1] if len(sys.argv) > 1 else "audit_phase1.json"
    stem = out_name.removesuffix(".json")
    data = snapshots.DATA_DIR
    ids = sorted(p.name for p in data.iterdir()
                 if (p / "instance.json").exists())
    results = {}
    for iid in ids:
        inst = snapshots.load_instance(iid)
        inst["instance_id"] = iid
        results[iid] = audit_instance(inst)
    golds = [r["gold"]["reward"] for r in results.values()]
    gate = {
        "gold_mean": round(sum(golds) / len(golds), 4) if golds else None,
        "gold_all_pass": all(r["gold"]["passed"] for r in results.values()),
        "battery_false_passes": sum(r["battery_false_passes"]
                                    for r in results.values()),
    }
    gate["gate_pass"] = bool(gate["gold_all_pass"]
                             and gate["battery_false_passes"] == 0)
    out = {"generated": datetime.now(timezone.utc).isoformat(),
           "gate": gate, "instances": results}
    build = ROOT / "build"
    history = build / "audit_runs"
    history.mkdir(parents=True, exist_ok=True)
    target = build / out_name
    if target.exists():
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        shutil.copyfile(target, history / f"{stem}_{stamp}.json")
    target.write_text(json.dumps(out, indent=2) + "\n")
    print(json.dumps(gate, indent=2))


if __name__ == "__main__":
    main()
