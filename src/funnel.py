"""Verification funnel (SPEC Section 4), applied in order; an instance
is discarded at the first failing stage and the stage is recorded.

Stages: licence -> build -> poc (determinism, 3/3 on the vulnerable
commit) -> gold (PoC blocked 3/3 on the gold commit + no new test
failures) -> mutants (>=3, each succeeds on vulnerable, blocked on gold)
-> leak (no gold-diff fragment in brief or PoC).

Phase 1 amendment (recorded in SPEC_v0.1.md): the regression suite is
the repository test module(s) relevant to the vulnerability, pinned in
the instance definition, not the repo's full suite.

Instance definitions live in instances_src/<id>/{instance.json,poc.py,
brief.txt}. Verified packages are written to data/<id>/ enriched with
baseline test results, surviving mutant payloads, and gold patch stats.

Candidates that cannot be attempted end-to-end (backend-specific
exploits with no matching local server, drivers that cannot express
the effect) are listed in instances_src/manual_discards.jsonl with the
stage and the reason; they are merged into the funnel log verbatim.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from . import mutants, snapshots, verifier

ROOT = snapshots.ROOT
SRC_DIR = ROOT / "instances_src"
BUILD = ROOT / "build"

PERMISSIVE = {"MIT", "BSD-3-Clause", "BSD-2-Clause", "Apache-2.0"}


def log_entry(**kw):
    BUILD.mkdir(exist_ok=True)
    with (BUILD / "funnel_log.jsonl").open("a") as fh:
        fh.write(json.dumps(kw) + "\n")


def gold_diff(inst) -> str:
    return verifier.load_gold_diff(inst)


def gold_stats(inst, diff: str):
    files = verifier.parse_diff(diff)
    added = sum(len(f["added"]) for f in files)
    deleted = sum(len(f["deleted"]) for f in files)
    return {"files": [f["path"] for f in files],
            "added": added, "deleted": deleted,
            "cross_file": len(files) > 1}


def licence_stage(inst, src_dir: Path) -> tuple[bool, str]:
    if inst["licence"] not in PERMISSIVE:
        return False, f"licence {inst['licence']} not permissive"
    repo = snapshots.repo_path(inst)
    for name in ("LICENSE", "LICENSE.txt", "LICENSE.rst", "COPYING",
                 "LICENCE", "LICENSE.md"):
        r = subprocess.run(["git", "show", f"{inst['fix_commit']}:{name}"],
                           cwd=str(repo), capture_output=True, text=True)
        if r.returncode == 0:
            head = r.stdout[:4000]
            # MIT texts in the wild often omit the "MIT License" title
            # line (Mako, setuptools); the permission grant sentence is
            # the operative MIT marker.
            needles = {"MIT": "Permission is hereby granted",
                       "BSD-3-Clause": "Redistribution",
                       "BSD-2-Clause": "Redistribution",
                       "Apache-2.0": "Apache License"}
            if needles[inst["licence"]] in head:
                return True, f"{name} at fix commit matches {inst['licence']}"
            return False, f"{name} found but licence marker missing"
    return False, "no licence file at fix commit"


def run_instance(instance_id: str) -> dict:
    src_dir = SRC_DIR / instance_id
    inst = json.loads((src_dir / "instance.json").read_text())
    inst["instance_id"] = instance_id
    rec = {"candidate": inst["cve"], "instance": instance_id,
           "package": inst["package"], "cwe": inst["cwe"], "stages": []}

    def stage(name, ok, detail):
        rec["stages"].append({"stage": name, "ok": ok, "detail": detail})
        print(f"[{instance_id}] {name}: {'OK' if ok else 'FAIL'} {detail}",
              flush=True)
        return ok

    ok, detail = licence_stage(inst, src_dir)
    if not stage("licence", ok, detail):
        rec["discard_stage"] = "licence"
        log_entry(**rec)
        return rec

    # ---- build: worktrees + pinned tests on the vulnerable commit ----------
    try:
        vuln = snapshots.ensure_worktree(inst, "vuln")
        gold = snapshots.ensure_worktree(inst, "gold")
    except Exception as e:
        stage("build", False, f"worktree error: {e}")
        rec["discard_stage"] = "build"
        log_entry(**rec)
        return rec
    # Baseline semantics (fixed after the first Phase 1 audit): the
    # pinned suite is the GOLD commit's test files run against the
    # vulnerable source -- security fixes update tests that asserted
    # the vulnerable behaviour, so a vulnerable-commit suite would
    # penalise the gold patch itself. See snapshots.overlay_gold_tests.
    snapshots.overlay_gold_tests(inst, vuln)
    base = verifier.run_tests(inst, vuln)
    if not stage("build", base["ran"],
                 f"pinned tests (gold suite) on vuln: total={base['total']} "
                 f"failed={len(base['failed'])}"):
        rec["discard_stage"] = "build"
        log_entry(**rec)
        return rec
    inst["baseline_failed_tests"] = sorted(base["failed"])
    inst["baseline_total_tests"] = base["total"]

    poc_src = src_dir / inst["poc_file"]
    # ---- poc determinism on vulnerable --------------------------------------
    codes = [snapshots.run_poc(inst, vuln, poc_src, inst["visible_payload"])
             for _ in range(3)]
    if not stage("poc", all(c == 0 for c in codes),
                 f"vuln poc exit codes {codes} (need 0,0,0)"):
        rec["discard_stage"] = "poc"
        log_entry(**rec)
        return rec
    # ---- gold verification ---------------------------------------------------
    gcodes = [snapshots.run_poc(inst, gold, poc_src, inst["visible_payload"])
              for _ in range(3)]
    gtest = verifier.run_tests(inst, gold)
    gnew = gtest["failed"] - set(inst["baseline_failed_tests"])
    ok = all(c == 1 for c in gcodes) and gtest["ran"] and not gnew
    if not stage("gold", ok,
                 f"gold poc codes {gcodes} (need 1,1,1); gold tests "
                 f"total={gtest['total']} new_failures={sorted(gnew)}"):
        rec["discard_stage"] = "gold"
        log_entry(**rec)
        return rec
    inst["gold_total_tests"] = gtest["total"]
    # ---- mutants --------------------------------------------------------------
    survivors = []
    details = {}
    for mp in mutants.generate(inst):
        v = snapshots.run_poc(inst, vuln, poc_src, mp)
        g = snapshots.run_poc(inst, gold, poc_src, mp) if v == 0 else None
        details[mp] = {"vuln": v, "gold": g}
        if v == 0 and g == 1:
            survivors.append(mp)
    if not stage("mutants", len(survivors) >= 3,
                 f"{len(survivors)} surviving mutants: {details}"):
        rec["discard_stage"] = "mutants"
        log_entry(**rec)
        return rec
    inst["mutant_payloads"] = survivors
    # ---- leak check -----------------------------------------------------------
    diff = gold_diff(inst)
    brief = (src_dir / "brief.txt").read_text()
    poc_text = poc_src.read_text()
    leaks = []
    for f in verifier.parse_diff(diff):
        for line in f["added"]:
            norm = re.sub(r"\s+", " ", line.strip())
            if len(norm) >= 30 and (norm in brief or norm in poc_text):
                leaks.append(norm[:80])
    if inst["fix_commit"][:12] in brief or inst["fix_commit"][:12] in poc_text:
        leaks.append("fix commit sha present")
    # The visible payload must not appear in the gold diff itself: the
    # first audit caught an instance whose payload was taken from a
    # doctest the fix adds, which made the gold patch trip the
    # verifier's payload-special-case rule. Caught here, at
    # construction, from now on.
    if verifier.payload_special_case(verifier.parse_diff(diff),
                                     inst["visible_payload"]):
        leaks.append("visible payload appears in gold diff")
    if not stage("leak", not leaks, f"leaks={leaks}"):
        rec["discard_stage"] = "leak"
        log_entry(**rec)
        return rec
    # ---- emit verified package --------------------------------------------------
    stats = gold_stats(inst, diff)
    inst["gold_patch_files"] = stats["files"]
    inst["gold_patch_added"] = stats["added"]
    inst["gold_patch_deleted"] = stats["deleted"]
    inst["cross_file"] = stats["cross_file"]
    out = snapshots.DATA_DIR / instance_id
    out.mkdir(parents=True, exist_ok=True)
    (out / "instance.json").write_text(json.dumps(inst, indent=2) + "\n")
    shutil.copyfile(poc_src, out / inst["poc_file"])
    shutil.copyfile(src_dir / "brief.txt", out / "brief.txt")
    (out / "gold_patch.diff").write_text(diff)
    rec["outcome"] = "verified"
    log_entry(**rec)
    print(f"[{instance_id}] VERIFIED -> {out}", flush=True)
    return rec


def main():
    if sys.argv[1:] == ["--manual-only"]:
        manual = SRC_DIR / "manual_discards.jsonl"
        n = 0
        for line in manual.read_text().splitlines():
            if line.strip():
                log_entry(**json.loads(line))
                n += 1
        print(f"manual entries appended: {n}")
        return
    only = sys.argv[1:] or None
    ids = sorted(p.name for p in SRC_DIR.iterdir()
                 if p.is_dir() and (p / "instance.json").exists())
    results = []
    for iid in ids:
        if only and iid not in only:
            continue
        results.append(run_instance(iid))
    manual = SRC_DIR / "manual_discards.jsonl"
    if manual.exists() and not only:
        for line in manual.read_text().splitlines():
            if line.strip():
                e = json.loads(line)
                log_entry(**e)
                results.append(e)
    n = sum(1 for r in results if r.get("outcome") == "verified")
    print(f"funnel: {n}/{len(results)} verified")


if __name__ == "__main__":
    main()
