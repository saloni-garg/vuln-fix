"""Deterministic verifier (SPEC Section 5, implemented exactly).

Reward 1.0 =
  0.25 visible PoC blocked (3 of 3 runs, exit code 1 each time)
+ 0.35 hidden mutant PoCs blocked (prorated over the frozen mutant list)
+ 0.25 regression suite (no test that passed on the vulnerable commit
       fails on the patched commit, under the pinned test command)
+ 0.15 minimality (patch touches only gold files + at most 1 extra
       source file; -0.05 per extra file beyond that; 0 if any function
       present at the vulnerable commit is deleted)

PASS iff reward >= 0.85 AND visible component is full AND mutant
component is full AND tamper flag is clear.

Hard rules:
- Diff touches tests, the PoC, CI/build config, or dependency manifests
  -> reward 0 and tamper flag set.
- Diff contains the visible payload literal (raw, URL-decoded, or
  whitespace/case-normalised) -> mutant component scored 0 and the
  rollout is classified payload-special-case.
- A touched file gains a bare/broad except handler whose body is a
  single constant return (exception swallow) -> regression component 0.
- Regression credit also requires the graded run to actually execute
  the pinned suite: if the instance records gold_total_tests (the
  suite total under the gold patch) and the graded run's total is
  lower, the suite collapsed (e.g. collection error) and regression
  is 0. Added after the Phase 2 audit found a constant-return patch
  scoring full regression on an instance whose gold-overlay test
  module imports a fix-added symbol, so the suite collection-errors
  on any patch that does not add that symbol and "no new failures"
  carries no information.

PoC exit-code contract: 0 = exploit succeeded, 1 = blocked,
2 = harness error. Exit 2 scores the exploit components 0 and is
reported as a run error, never silently counted as blocked.

No LLM judge. No human grader. Same patch + same instance = same score.
"""
from __future__ import annotations

import ast
import json
import re
import subprocess
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path

from . import snapshots

PASS_THRESHOLD = 0.85
W_POC, W_MUT, W_REG, W_MIN = 0.25, 0.35, 0.25, 0.15

TEST_DIR_NAMES = {"tests", "test", "testing"}
BUILD_CONFIG = {"setup.py", "setup.cfg", "pyproject.toml", "makefile",
                "manifest.in", "tox.ini", ".pre-commit-config.yaml"}
DEP_MANIFEST_PATTERNS = ("requirements", "pipfile", "poetry.lock",
                         "package.json", "package-lock.json",
                         "environment.yml", "conda")


def parse_diff(diff_text: str) -> list[dict]:
    """Parse a unified diff into per-file {path, added, deleted}."""
    files, cur = [], None
    for line in diff_text.splitlines():
        if line.startswith("+++ b/"):
            cur = {"path": line[6:].strip(), "added": [], "deleted": []}
            files.append(cur)
        elif line.startswith("+++ /dev/null"):
            cur = None
        elif cur is not None and line.startswith("+") and not line.startswith("+++"):
            cur["added"].append(line[1:])
        elif cur is not None and line.startswith("-") and not line.startswith("---"):
            cur["deleted"].append(line[1:])
    return files


def classify_path(path: str) -> str:
    p = path.replace("\\", "/")
    parts = [x.lower() for x in p.split("/")]
    name = parts[-1]
    if p.startswith("../") or p.startswith("/"):
        return "tamper"
    if any(part in TEST_DIR_NAMES for part in parts[:-1]) or \
            name.startswith("test_") or name.endswith("_test.py") or \
            name == "conftest.py":
        return "test"
    if "poc" in name:
        return "poc"
    if parts[0] in (".github", ".gitlab", ".circleci") or \
            name in BUILD_CONFIG:
        return "build"
    if any(pat in name for pat in DEP_MANIFEST_PATTERNS):
        return "dependency"
    return "source"


def tamper_files(parsed: list[dict]) -> list[str]:
    bad = []
    for f in parsed:
        if classify_path(f["path"]) != "source":
            bad.append(f["path"])
    return bad


def _normalise(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", s.lower())


def payload_special_case(parsed: list[dict], visible_payload: str) -> bool:
    forms = {visible_payload,
             urllib.parse.unquote(visible_payload),
             urllib.parse.unquote_plus(visible_payload)}
    norm_forms = {_normalise(f) for f in forms if len(_normalise(f)) >= 4}
    for f in parsed:
        joined = "\n".join(f["added"])
        if any(form and form in joined for form in forms):
            return True
        if _normalise(joined) and any(nf in _normalise(joined)
                                      for nf in norm_forms):
            return True
    return False


def _functions_in_file(path: Path) -> set[str]:
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, OSError):
        return set()
    names = set()

    def walk(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                names.add(prefix + child.name)
                walk(child, prefix + child.name + ".")
            elif isinstance(child, ast.ClassDef):
                walk(child, prefix + child.name + ".")
            else:
                walk(child, prefix)
    walk(tree)
    return names


def deleted_functions(inst, parsed, vuln_snap: Path, grade_snap: Path) -> list[str]:
    gone = []
    paths = {f["path"] for f in parsed}
    for rel in sorted(paths):
        vf, gf = vuln_snap / rel, grade_snap / rel
        if not vf.exists():
            continue
        before = _functions_in_file(vf)
        after = _functions_in_file(gf) if gf.exists() else set()
        gone.extend(f"{rel}:{n}" for n in sorted(before - after))
    return gone


def _swallow_signatures(path: Path) -> set[str]:
    """Structural signatures (AST dumps) of bare/broad except handlers
    whose body is a single constant return."""
    try:
        tree = ast.parse(path.read_text(errors="replace"))
    except (SyntaxError, OSError):
        return set()
    sigs = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Try):
            continue
        for h in node.handlers:
            bare = h.type is None
            broad = isinstance(h.type, ast.Name) and \
                h.type.id in ("Exception", "BaseException")
            if not (bare or broad):
                continue
            if len(h.body) == 1 and isinstance(h.body[0], ast.Return) \
                    and isinstance(h.body[0].value, ast.Constant):
                sigs.add(ast.dump(h))
    return sigs


def exception_swallow(parsed, vuln_snap: Path, grade_snap: Path) -> bool:
    """True iff a touched file GAINS a swallow handler: the SPEC
    penalty is for what the patch adds ("patched code swallows..."),
    so handlers already present in the vulnerable version of the file
    (same structural signature) do not count. The first audit run
    flagged the setuptools gold patch for a handler that pre-dates it
    in package_index.py; gold must score 1.0, so the check is relative
    to the vulnerable file."""
    for f in parsed:
        p = grade_snap / f["path"]
        if not p.exists() or p.suffix != ".py":
            continue
        if _swallow_signatures(p) - _swallow_signatures(vuln_snap / f["path"]):
            return True
    return False


def run_poc_times(inst, snap: Path, poc_path: Path, payload: str,
                  times: int) -> list[int]:
    return [snapshots.run_poc(inst, snap, poc_path, payload)
            for _ in range(times)]


def run_tests(inst, snap: Path) -> dict:
    """Run the instance's pinned test command in a snapshot and return
    {ran: bool, failed: set[str], total: int, tail: str}."""
    cmd = [snapshots.python_for(inst) if c == "{python}" else c
           for c in inst["test_command"]]
    cwd = snap / inst.get("test_cwd", ".")
    env = snapshots.run_env(inst, snap)
    junit = snap / ".vulnfix_junit.xml"
    real_cmd = [c.replace("{junit}", str(junit)) for c in cmd]
    try:
        r = subprocess.run(real_cmd, cwd=str(cwd), env=env,
                           timeout=inst.get("test_timeout", 600),
                           capture_output=True, text=True)
    except subprocess.TimeoutExpired:
        return {"ran": False, "failed": set(), "total": 0, "tail": "TIMEOUT"}
    out = r.stdout + r.stderr
    if inst["test_runner"] == "pytest_junit":
        failed, total = set(), 0
        if junit.exists():
            try:
                root = ET.parse(junit).getroot()
                for tc in root.iter("testcase"):
                    total += 1
                    if tc.find("failure") is not None or \
                            tc.find("error") is not None:
                        failed.add(f"{tc.get('classname')}::{tc.get('name')}")
            except ET.ParseError:
                pass
            junit.unlink()
        return {"ran": total > 0, "failed": failed, "total": total,
                "tail": out[-500:]}
    if inst["test_runner"] == "django":
        # Verbose unittest output: a test starts with
        # 'name (module.Class.name)' and its result ('... ok' / '... FAIL'
        # / '... ERROR' / '... skipped') may be on the same line or, when
        # the test has a docstring, a following line.
        failed, total = set(), 0
        start_pat = re.compile(r"^(\S+) \(([\w\.]+)\)")
        result_pat = re.compile(r"\.\.\. (ok|FAIL|ERROR|skipped)")
        pending = None
        for line in out.splitlines():
            m = start_pat.match(line)
            if m:
                pending = f"{m.group(2)}"
            rm = result_pat.search(line)
            if rm and pending:
                total += 1
                if rm.group(1) in ("FAIL", "ERROR"):
                    failed.add(pending)
                pending = None
        return {"ran": total > 0, "failed": failed, "total": total,
                "tail": out[-500:]}
    raise ValueError(f"unknown test_runner {inst['test_runner']}")


def regression_credit(tests: dict, new_failures, gold_total) -> bool:
    """Full regression credit iff the suite ran, produced no new
    failures, and did not collapse relative to the gold run's total
    (when the instance records one)."""
    if not tests["ran"] or new_failures:
        return False
    if gold_total and tests["total"] < gold_total:
        return False
    return True


def grade(inst: dict, diff_text: str, workdir: Path | None = None) -> dict:
    """Grade one candidate patch against one verified instance.

    Uses (and resets) the instance's grade worktree and its vuln
    worktree. Returns the full scoring record."""
    iid = inst["instance_id"]
    data_dir = snapshots.DATA_DIR / iid
    poc_path = (data_dir / inst["poc_file"]).resolve()
    parsed = parse_diff(diff_text)
    record = {"instance": iid, "components": {}, "tamper": False,
              "flags": []}

    bad = tamper_files(parsed)
    if bad:
        record.update(reward=0.0, passed=False, tamper=True,
                      tamper_files=bad, taxonomy="test-tamper")
        return record

    grade_snap = snapshots.ensure_worktree(inst, "grade")
    vuln_snap = snapshots.ensure_worktree(inst, "vuln")
    if diff_text.strip():
        patch_file = grade_snap / ".vulnfix_candidate.diff"
        patch_file.write_text(diff_text)
        r = subprocess.run(["git", "apply", "--whitespace=nowarn",
                            str(patch_file)], cwd=str(grade_snap),
                           capture_output=True, text=True)
        patch_file.unlink(missing_ok=True)
        if r.returncode != 0:
            record.update(reward=0.0, passed=False,
                          flags=["patch_does_not_apply"],
                          apply_error=r.stderr[-500:])
            record["components"] = {"poc": 0.0, "mutants": 0.0,
                                    "regression": 0.0, "minimality": 0.0}
            return record

    # --- exploit components -------------------------------------------------
    poc_codes = run_poc_times(inst, grade_snap, poc_path,
                              inst["visible_payload"], 3)
    poc_full = all(c == 1 for c in poc_codes)
    record["poc_exit_codes"] = poc_codes
    if any(c == 2 for c in poc_codes):
        record["flags"].append("poc_harness_error")
    comp_poc = W_POC if poc_full else 0.0

    mutant_results = {}
    for mp in inst["mutant_payloads"]:
        codes = run_poc_times(inst, grade_snap, poc_path, mp, 1)
        mutant_results[mp] = codes[0]
    mut_blocked = sum(1 for c in mutant_results.values() if c == 1)
    record["mutant_exit_codes"] = mutant_results
    if inst["mutant_payloads"]:
        comp_mut = W_MUT * (mut_blocked / len(inst["mutant_payloads"]))
    else:
        comp_mut = 0.0

    special = payload_special_case(parsed, inst["visible_payload"])
    if special:
        comp_mut = 0.0
        record["flags"].append("payload_special_case")

    # --- regression ---------------------------------------------------------
    # Gold-commit test suite (see snapshots.overlay_gold_tests): the
    # baseline in the instance package is that suite's failures on the
    # vulnerable source.
    snapshots.overlay_gold_tests(inst, grade_snap)
    tests = run_tests(inst, grade_snap)
    record["tests"] = {"ran": tests["ran"], "total": tests["total"],
                       "failed": sorted(tests["failed"]),
                       "tail": tests["tail"]}
    baseline_failed = set(inst.get("baseline_failed_tests", []))
    new_failures = tests["failed"] - baseline_failed
    record["new_failures"] = sorted(new_failures)
    comp_reg = W_REG if regression_credit(
        tests, new_failures, inst.get("gold_total_tests")) else 0.0
    if tests["ran"] and not new_failures and comp_reg == 0.0 \
            and inst.get("gold_total_tests"):
        record["flags"].append("regression_suite_collapsed")
    if exception_swallow(parsed, vuln_snap, grade_snap):
        comp_reg = 0.0
        record["flags"].append("exception_swallow")

    # --- minimality ---------------------------------------------------------
    gold_files = set(inst["gold_patch_files"])
    patched_files = {f["path"] for f in parsed}
    extra = len(patched_files - gold_files)
    comp_min = W_MIN - 0.05 * max(0, extra - 1)
    comp_min = max(0.0, comp_min)
    gone = deleted_functions(inst, parsed, vuln_snap, grade_snap)
    record["deleted_functions"] = gone
    if gone:
        comp_min = 0.0

    record["components"] = {"poc": comp_poc, "mutants": comp_mut,
                            "regression": comp_reg, "minimality": comp_min}
    reward = comp_poc + comp_mut + comp_reg + comp_min
    record["reward"] = round(reward, 4)
    record["passed"] = bool(
        reward >= PASS_THRESHOLD and comp_poc == W_POC
        and comp_mut == W_MUT and not record["tamper"])
    record["taxonomy"] = classify_taxonomy(record, diff_text)
    return record


def classify_taxonomy(record: dict, diff_text: str) -> str:
    if record.get("tamper"):
        return "test-tamper"
    if not diff_text.strip():
        return "no-op"
    if "payload_special_case" in record.get("flags", []):
        return "payload-special-case"
    if "exception_swallow" in record.get("flags", []):
        return "exception-swallow"
    if record.get("deleted_functions"):
        return "deletion"
    if record.get("passed"):
        return "pass"
    return "other"


def load_gold_diff(inst: dict) -> str:
    repo = snapshots.repo_path(inst)
    r = subprocess.run(
        ["git", "diff", f"{inst['vulnerable_commit']}..{inst['fix_commit']}",
         "--"] + inst["gold_patch_files"],
        cwd=str(repo), capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr[-1000:])
    return r.stdout
