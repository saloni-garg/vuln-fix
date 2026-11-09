"""Snapshot management: materialise vulnerable / gold / grade worktrees
from the local bare-ish clones under work/repos/.

Grading never touches the network: clones are fetched during mining and
setup only; after that every run is local. Graded subprocesses also get
deliberately broken proxy variables (see run_env) as a belt-and-braces
egress discouragement -- that is an env-level guard, not an OS-level
network namespace, and the Phase 1 report says so.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPOS_DIR = ROOT / "work" / "repos"
SNAP_DIR = ROOT / "work" / "snapshots"
DATA_DIR = ROOT / "data"


def sh(cmd, cwd=None, env=None, timeout=300, check=True):
    r = subprocess.run(cmd, cwd=cwd, env=env, timeout=timeout,
                       capture_output=True, text=True)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"command failed ({r.returncode}): {' '.join(map(str, cmd))}\n"
            f"stdout: {r.stdout[-2000:]}\nstderr: {r.stderr[-2000:]}")
    return r


def load_instance(instance_id: str) -> dict:
    p = DATA_DIR / instance_id / "instance.json"
    if not p.exists():
        p = ROOT / "instances_src" / instance_id / "instance.json"
    return json.loads(p.read_text())


def repo_path(inst: dict) -> Path:
    return REPOS_DIR / inst["repo_local"]


def ensure_worktree(inst: dict, kind: str) -> Path:
    """kind in {vuln, gold, grade}. Returns the worktree path, creating or
    resetting it as needed. Reset = checkout vulnerable commit + clean."""
    iid = inst["instance_id"]
    dest = SNAP_DIR / iid / kind
    repo = repo_path(inst)
    commits = {"vuln": inst["vulnerable_commit"],
               "gold": inst["fix_commit"],
               "grade": inst["vulnerable_commit"]}
    commit = commits[kind]
    if dest.exists() and (dest / ".git").exists():
        sh(["git", "checkout", "--", "."], cwd=dest, check=False)
        sh(["git", "clean", "-fd"], cwd=dest, check=False)
        sh(["git", "checkout", "--detach", commit], cwd=dest)
    else:
        dest.parent.mkdir(parents=True, exist_ok=True)
        if dest.exists():
            shutil.rmtree(dest)
        sh(["git", "worktree", "add", "--detach", str(dest), commit],
           cwd=repo, timeout=600)
    return dest


def _is_test_path(path: str) -> bool:
    parts = [x.lower() for x in path.replace("\\", "/").split("/")]
    name = parts[-1]
    return any(p in {"tests", "test", "testing"} for p in parts[:-1]) \
        or name.startswith("test_") or name.endswith("_test.py") \
        or name == "conftest.py"


def overlay_gold_tests(inst: dict, snap: Path) -> None:
    """Replace the test files in a snapshot with the fix commit's
    versions (files changed between the vulnerable and fix commits
    that are test files).

    Rationale (SWE-bench semantics): security fixes routinely update
    the existing tests that asserted the vulnerable behaviour, so a
    regression suite taken from the vulnerable commit penalises the
    gold patch itself for upstream test changes. The regression
    baseline is therefore the gold commit's test suite run against the
    vulnerable source, and graded runs use that same suite. Candidate
    patches that touch test files are already hard-zeroed by the
    verifier's tamper rule before this overlay is applied, so the
    overlay cannot be gamed by a candidate.
    """
    repo = repo_path(inst)
    r = sh(["git", "diff", "--name-only",
            f"{inst['vulnerable_commit']}..{inst['fix_commit']}"],
           cwd=repo)
    for path in r.stdout.splitlines():
        if not _is_test_path(path):
            continue
        exists = sh(["git", "cat-file", "-e",
                     f"{inst['fix_commit']}:{path}"],
                    cwd=repo, check=False).returncode == 0
        if exists:
            sh(["git", "checkout", inst["fix_commit"], "--", path],
               cwd=snap)
        else:
            p = snap / path
            if p.exists():
                p.unlink()


def run_env(inst: dict, snap: Path) -> dict:
    env = dict(os.environ)
    pp = [str(snap / p) if p != "." else str(snap)
          for p in inst.get("pythonpath", ["."])]
    if env.get("PYTHONPATH"):
        pp.append(env["PYTHONPATH"])
    env["PYTHONPATH"] = os.pathsep.join(pp)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    # Egress discouragement for graded runs (mining/setup excluded).
    env["http_proxy"] = "http://127.0.0.1:9"
    env["https_proxy"] = "http://127.0.0.1:9"
    env["HTTP_PROXY"] = "http://127.0.0.1:9"
    env["HTTPS_PROXY"] = "http://127.0.0.1:9"
    env["no_proxy"] = ""
    env.update(inst.get("env", {}))
    return env


def python_for(inst: dict) -> str:
    """Interpreter for graded runs: the instance's venv if it names one
    (era-specific dependency sets, e.g. aiohttp), else the project venv
    (which carries the test dependencies installed during setup),
    falling back to python3."""
    named = inst.get("venv")
    if named:
        p = ROOT / named / "bin" / "python"
        if p.exists():
            return str(p)
    venv = ROOT / ".venv" / "bin" / "python"
    if inst.get("use_venv", True) and venv.exists():
        return str(venv)
    return "python3"


def run_poc(inst: dict, snap: Path, poc_path: Path, payload: str,
            timeout: int = 120) -> int:
    """Run a PoC script against a snapshot. PoC exit-code contract:
    0 = exploit succeeded, 1 = blocked, 2 = harness error. Callers treat
    only 1 as blocked."""
    env = run_env(inst, snap)
    r = subprocess.run(
        [python_for(inst), str(poc_path), "--payload", payload],
        cwd=str(snap), env=env, timeout=timeout,
        capture_output=True, text=True)
    return r.returncode
