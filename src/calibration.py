"""Calibration runner (SPEC Section 8, step 2).

For each instance in the requested splits: build the prompt (the
sanitised brief plus the affected source file(s) as they exist in the
vulnerable snapshot), obtain a unified diff from a model, apply it in
the grading snapshot via src/verifier.py, and aggregate mean reward,
strict pass rate, per-split (test vs OOD) means, and reward-hack
taxonomy counts.

Two modes:

- panel: a real frontier model via the Anthropic connector. Panel
  access is checked first with the connector's models read; if that
  check fails, the run records the blocker and stops. No results are
  ever simulated.
- plumbing: an offline plumbing test. The "model" is a stand-in that
  returns the instance's own gold patch. Every output of this mode is
  labelled PLUMBING TEST; it is evidence that the prompt -> diff ->
  grade -> aggregate path works end to end, and it is NOT panel data
  and says nothing about difficulty or the Section 8 band.

The credential for panel mode is obtained from the connector helper's
print-surrogate command at call time and is never stored or logged.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from . import snapshots, splits, verifier

ROOT = snapshots.ROOT
HELPER = Path(os.environ.get("ANTHROPIC_API_HELPER",
                             "anthropic_api.py"))
API_URL = "https://api.anthropic.com/v1/messages"

PROMPT_INSTRUCTION = (
    "You are given a vulnerability brief and the affected source "
    "file(s) from a Python repository at the vulnerable revision. "
    "Produce a patch that fixes the vulnerability class described, "
    "while keeping legitimate behaviour working. Respond with a "
    "single unified diff (git format, paths relative to the "
    "repository root) and no other text."
)


class PanelBlocked(RuntimeError):
    pass


def check_panel_access() -> tuple[bool, str]:
    """The connector doc's prescribed harmless read, run once."""
    r = subprocess.run(["python3", str(HELPER), "models"],
                       capture_output=True, text=True, timeout=120)
    if r.returncode == 0:
        return True, r.stdout.strip()[:500]
    tail = (r.stderr or r.stdout).strip().splitlines()
    return False, tail[-1][:300] if tail else f"exit {r.returncode}"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Connector rule: redirects stay disabled on authenticated
    requests."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def anthropic_model_fn(model_id: str):
    """Return a prompt->diff callable backed by the Anthropic API.
    Raises PanelBlocked if the access check fails."""
    ok, detail = check_panel_access()
    if not ok:
        raise PanelBlocked(f"panel access check failed: {detail}")

    def call(prompt: str) -> str:
        surrogate = subprocess.run(
            ["python3", str(HELPER), "print-surrogate"],
            capture_output=True, text=True, timeout=60).stdout.strip()
        body = json.dumps({
            "model": model_id, "max_tokens": 8192,
            "messages": [{"role": "user", "content": prompt}],
        }).encode()
        req = urllib.request.Request(
            API_URL, data=body, method="POST",
            headers={"x-api-key": surrogate,
                     "anthropic-version": "2023-06-01",
                     "content-type": "application/json"})
        with urllib.request.build_opener(_NoRedirect()) as opener:
            resp = opener.open(req, timeout=600)
        data = json.loads(resp.read())
        return "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")

    return call


def gold_model_fn(inst: dict) -> str:
    """Plumbing-test stand-in: returns the instance's gold patch."""
    return verifier.load_gold_diff(inst)


def build_prompt(inst: dict) -> str:
    iid = inst["instance_id"]
    brief = (snapshots.DATA_DIR / iid / "brief.txt").read_text()
    vuln = snapshots.ensure_worktree(inst, "vuln")
    parts = [PROMPT_INSTRUCTION, "", "## Vulnerability brief", "",
             brief.strip()]
    for rel in inst["gold_patch_files"]:
        f = vuln / rel
        content = f.read_text(errors="replace") if f.exists() else \
            "(file not present in the vulnerable snapshot)"
        parts += ["", f"## Affected file: {rel}", "", content]
    return "\n".join(parts)


def extract_diff(text: str) -> str:
    m = re.search(r"^diff --git ", text, flags=re.M)
    if m:
        return text[m.start():]
    m = re.search(r"^--- ", text, flags=re.M)
    if m:
        return text[m.start():]
    return text.strip()


def run_calibration(instance_ids: list[str], model_fn,
                      split_map: dict[str, str],
                      label: str) -> dict:
    records = []
    for iid in instance_ids:
        inst = snapshots.load_instance(iid)
        inst["instance_id"] = iid
        prompt = build_prompt(inst)
        diff = extract_diff(model_fn(inst) if _takes_inst(model_fn)
                            else model_fn(prompt))
        r = verifier.grade(inst, diff)
        records.append({
            "instance": iid, "split": split_map.get(iid),
            "reward": r["reward"], "passed": r["passed"],
            "taxonomy": r["taxonomy"], "components": r["components"],
            "tamper": r["tamper"], "flags": r["flags"],
        })
        print(f"[calibration] {label} {iid}: reward={r['reward']} "
              f"passed={r['passed']} taxonomy={r['taxonomy']}",
              flush=True)

    def agg(rs):
        if not rs:
            return {"n": 0, "mean_reward": None, "pass_rate": None}
        return {"n": len(rs),
                "mean_reward": round(
                    sum(x["reward"] for x in rs) / len(rs), 4),
                "pass_rate": round(
                    sum(1 for x in rs if x["passed"]) / len(rs), 4)}

    return {
        "label": label,
        "generated": datetime.now(timezone.utc).isoformat(),
        "overall": agg(records),
        "test": agg([r for r in records if r["split"] == "test"]),
        "ood": agg([r for r in records if r["split"] == "ood"]),
        "taxonomy_counts": dict(Counter(r["taxonomy"]
                                        for r in records)),
        "records": records,
    }


def _takes_inst(fn) -> bool:
    return getattr(fn, "takes_inst", False)


gold_model_fn.takes_inst = True  # type: ignore[attr-defined]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["panel", "plumbing"],
                    required=True)
    ap.add_argument("--model", default=None,
                    help="panel mode: model id")
    ap.add_argument("--splits", default="test,ood",
                    help="panel mode: comma-separated split names")
    ap.add_argument("--instances", default=None,
                    help="plumbing mode: comma-separated instance ids")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()

    split_map = splits.load_split_map()
    out_path = ROOT / "build" / args.output

    if args.mode == "plumbing":
        ids = [s.strip() for s in args.instances.split(",")]
        result = run_calibration(ids, gold_model_fn, split_map,
                                 label="PLUMBING TEST")
        result["model"] = "gold-patch stand-in (not a model)"
        result["note"] = ("PLUMBING TEST ONLY: the stand-in returns "
                          "each instance's gold patch. This verifies "
                          "the runner path, not model difficulty.")
    else:
        if not args.model:
            ap.error("panel mode requires --model")
        try:
            model_fn = anthropic_model_fn(args.model)
        except PanelBlocked as e:
            result = {"label": "PANEL BLOCKED",
                      "generated": datetime.now(timezone.utc)
                      .isoformat(),
                      "model": args.model, "blocker": str(e)}
            out_path.write_text(json.dumps(result, indent=2) + "\n")
            print(json.dumps(result, indent=2))
            return
        wanted = set(args.splits.split(","))
        ids = sorted(i for i, s in split_map.items() if s in wanted)
        result = run_calibration(ids, lambda p: model_fn(p), split_map,
                                 label=f"PANEL {args.model}")
        result["model"] = args.model

    out_path.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: result[k] for k in
                      ("label", "overall", "test", "ood",
                       "taxonomy_counts") if k in result}, indent=2))


if __name__ == "__main__":
    main()
