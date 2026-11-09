"""Mining (SPEC Section 4, source stage).

Queries the OSV database (which mirrors GHSA) for a seed set of Python
packages, keeps vulnerabilities whose CWE is CWE-89 or CWE-22, dedupes
by CVE id, and tries to resolve a fix commit from, in order:
  1. OSV GIT ranges / FIX references naming a commit,
  2. `git log --grep=<CVE>` in the local clone,
  3. a small hand-checked override table (OVERRIDES) for commits found
     by reading the local history during Phase 1 (each entry is
     verifiable with `git show`).

Every mined candidate gets a funnel-log entry. Candidates that are not
shortlisted for the Phase 1 prototype are recorded as triage discards
with the reason; shortlisted candidates without a resolved fix commit
are recorded as resolution discards. Neither is silently dropped.

Output: build/candidates.jsonl, and triage/resolution entries appended
to build/funnel_log.jsonl (the funnel runner appends the rest).
"""
from __future__ import annotations

import json
import re
import subprocess
import urllib.request
from pathlib import Path

from . import snapshots

ROOT = snapshots.ROOT
BUILD = ROOT / "build"
TARGET_CWES = {"CWE-89", "CWE-22"}
PERMISSIVE = {"MIT", "BSD-3-Clause", "BSD-2-Clause", "Apache-2.0"}

# pypi name -> (repo url, local clone dir, licence, triage)
# triage: "shortlist" or a discard reason for the Phase 1 prototype.
PACKAGES = {
    "django": ("https://github.com/django/django.git", None, "BSD-3-Clause", "shortlist"),
    "mako": ("https://github.com/sqlalchemy/mako.git", "mako", "MIT", "shortlist"),
    "piccolo": ("https://github.com/piccolo-orm/piccolo.git", "piccolo", "MIT", "shortlist"),
    "pip": ("https://github.com/pypa/pip.git", "pip", "MIT", "shortlist"),
    "setuptools": ("https://github.com/pypa/setuptools.git", "setuptools", "MIT", "shortlist"),
    "aiohttp": ("https://github.com/aio-libs/aiohttp.git", "aiohttp", "Apache-2.0", "shortlist"),
    "gitpython": ("https://github.com/gitpython-developers/GitPython.git", "gitpython", "BSD-3-Clause", "shortlist"),
    "dulwich": ("https://github.com/dulwich/dulwich.git", "dulwich", "Apache-2.0", "shortlist"),
    "mlflow": ("https://github.com/mlflow/mlflow.git", None, "Apache-2.0", "triage: very large dependency stack; server-style PoCs not unit-level"),
    "gradio": ("https://github.com/gradio-app/gradio.git", None, "Apache-2.0", "triage: very large dependency stack; PoCs are server-level"),
    "langchain": ("https://github.com/langchain-ai/langchain.git", None, "MIT", "triage: PoCs require LLM-chain scaffolding, not a unit-level oracle"),
    "sanic": ("https://github.com/sanic-org/sanic.git", None, "MIT", "triage: 2022-era codebase, pinned deps do not support the Python 3.12 sandbox"),
    "starlette": ("https://github.com/encode/starlette.git", None, "BSD-3-Clause", "triage: the CWE-22 entry is Windows-specific"),
    "werkzeug": ("https://github.com/pallets/werkzeug.git", None, "BSD-3-Clause", "triage: recent CWE-22 entry is Windows-specific; the other is from 2019"),
    "tortoise-orm": ("https://github.com/tortoise/tortoise-orm.git", None, "MIT", "triage: 2020-era codebase, build on Python 3.12 not expected"),
    "ansible": ("https://github.com/ansible/ansible.git", None, "GPL-3.0", "triage: copyleft licence"),
    "glance": ("https://github.com/openstack/glance.git", None, "Apache-2.0", "triage: OpenStack service stack, not unit-level"),
    "pillow": ("https://github.com/python-pillow/Pillow.git", None, "HPND", "triage: C extension build; single old entry"),
    "transformers": ("https://github.com/huggingface/transformers.git", None, "Apache-2.0", "triage: very large dependency stack"),
    "bentoml": ("https://github.com/bentoml/BentoML.git", None, "Apache-2.0", "triage: large dependency stack, server-level PoCs"),
    "poetry": ("https://github.com/python-poetry/poetry.git", None, "MIT", "triage: entries depend on specific old CPython tarfile behaviour not present in the sandbox interpreter"),
    "mako-note": (None, None, None, None),
}
PACKAGES.pop("mako-note")

# Hand-checked fix commits (verify with `git show <sha>` in the clone).
OVERRIDES = {
    "CVE-2025-64459": "ac9fcf6eb2c909f4150c5287808f49170ce1f9e2",
    "CVE-2025-57833": "4c044fcc866ec226f612c475950b690b0139d243",
    "CVE-2024-42005": "c87bfaacf8fb84984243b5055dc70f97996cb115",
    "CVE-2026-1287": "3e68ccdc11c127758745ddf0b4954990b14892bc",
    "CVE-2025-59682": "ed8fc39d77465eddbde1191a054ae965f6a8a584",
    "CVE-2025-59681": "52fbae0a4ddc2f74d01de67e62e26c0925d8b2da",
    "CVE-2025-13372": "479415ce52",  # short sha resolved in clone at runtime
    "CVE-2026-41205": "e05ac61989a7fb9dd7dcde6cfd72dc48328719a3",
    "CVE-2024-39330": "2b00edc0151a660d1eb86da4059904a0fc4e095e",
    "CVE-2023-41040": "64ebb9fcdfbe48d5d61141a557691fd91f1e88d6",
}

DJANGO_BRANCH_CLONES = ["django-5.2", "django-5.1", "django-4.2"]


def osv_query(package: str) -> list[dict]:
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=json.dumps({"package": {"name": package,
                                       "ecosystem": "PyPI"}}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.load(r).get("vulns", [])


def cve_of(vuln: dict) -> str | None:
    for a in vuln.get("aliases", []):
        if a.startswith("CVE-"):
            return a
    return vuln["id"] if vuln["id"].startswith("CVE-") else None


def fix_from_osv(vuln: dict) -> str | None:
    for a in vuln.get("affected", []):
        for r in a.get("ranges", []):
            if r.get("type") == "GIT":
                for e in r.get("events", []):
                    if "fixed" in e and re.fullmatch(r"[0-9a-f]{40}", e["fixed"]):
                        return e["fixed"]
    for ref in vuln.get("references", []):
        if ref.get("type") == "FIX":
            m = re.search(r"/commit/([0-9a-f]{40})", ref.get("url", ""))
            if m:
                return m.group(1)
    return None


def fix_from_gitlog(repo_dirs: list[str], cve: str) -> str | None:
    for d in repo_dirs:
        repo = snapshots.REPOS_DIR / d
        if not repo.exists():
            continue
        r = subprocess.run(["git", "log", "--all", "--format=%H %s",
                            "-i", "--grep", cve],
                           cwd=str(repo), capture_output=True, text=True)
        for line in r.stdout.splitlines():
            sha, _, subject = line.partition(" ")
            if f"Fixed {cve}" in subject:
                return sha
    return None


def resolve_sha(repo_dirs: list[str], sha: str) -> str | None:
    for d in repo_dirs:
        repo = snapshots.REPOS_DIR / d
        if not repo.exists():
            continue
        r = subprocess.run(["git", "rev-parse", "--verify", f"{sha}^{{commit}}"],
                           cwd=str(repo), capture_output=True, text=True)
        if r.returncode == 0:
            return r.stdout.strip()
    return None


def mine() -> tuple[list[dict], list[dict]]:
    candidates, log = [], []
    seen: dict[str, dict] = {}
    for pkg, (url, local, licence, triage) in PACKAGES.items():
        try:
            vulns = osv_query(pkg)
        except Exception as e:  # mining must record, not crash
            log.append({"candidate": pkg, "stage": "mining",
                        "outcome": "error", "reason": str(e)})
            continue
        # Group all OSV entries (GHSA + PYSEC) per CVE first: the CWE
        # list typically lives on the GHSA entry while the GIT fix range
        # lives on the PYSEC entry, so filtering entry-by-entry loses
        # fix commits. (Found in Phase 1 build; see PHASE1_REPORT.md.)
        grouped: dict[str, list[dict]] = {}
        for v in vulns:
            cve = cve_of(v)
            if cve is not None:
                grouped.setdefault(cve, []).append(v)
        for cve, entries in grouped.items():
            cwes = []
            for v in entries:
                for c in v.get("database_specific", {}).get("cwe_ids", []):
                    if c in TARGET_CWES and c not in cwes:
                        cwes.append(c)
            if not cwes:
                continue
            v = entries[0]
            key = (pkg, cve)
            fixed_versions = []
            for entry in entries:
                for a in entry.get("affected", []):
                    for r in a.get("ranges", []):
                        for e in r.get("events", []):
                            if "fixed" in e and r.get("type") == "ECOSYSTEM":
                                fixed_versions.append(e["fixed"])
            rec = seen.get(key)
            if rec is None:
                rec = {"package": pkg, "cve": cve, "ghsa": v["id"],
                       "cwe": cwes[0], "summary": v.get("summary", ""),
                       "published": v.get("published", "")[:10],
                       "repo_url": url, "repo_local": local,
                       "licence": licence, "triage": triage,
                       "fixed_versions": fixed_versions,
                       "fix_commit": None, "fix_source": None}
                seen[key] = rec
                candidates.append(rec)
            else:
                rec["fixed_versions"] = sorted(
                    set(rec["fixed_versions"]) | set(fixed_versions))
            for entry in entries:
                sha = fix_from_osv(entry)
                if sha and rec["fix_commit"] is None:
                    rec["fix_commit"], rec["fix_source"] = sha, "osv"
    # resolution pass for shortlisted candidates
    for rec in candidates:
        if rec["triage"] != "shortlist":
            log.append({"candidate": rec["cve"], "package": rec["package"],
                        "discard_stage": "triage", "reason": rec["triage"],
                        "cwe": rec["cwe"]})
            continue
        dirs = DJANGO_BRANCH_CLONES if rec["package"] == "django" \
            else [rec["repo_local"]]
        rec["repo_dirs"] = dirs
        if rec["cve"] in OVERRIDES:
            full = resolve_sha(dirs, OVERRIDES[rec["cve"]])
            if full:
                rec["fix_commit"], rec["fix_source"] = full, "override+git"
        if rec["fix_commit"] is None:
            sha = fix_from_gitlog(dirs, rec["cve"])
            if sha:
                rec["fix_commit"], rec["fix_source"] = sha, "gitlog"
        if rec["fix_commit"] is None:
            log.append({"candidate": rec["cve"], "package": rec["package"],
                        "discard_stage": "resolution",
                        "reason": "no fix commit in OSV GIT ranges/FIX "
                                  "references, none in local git history "
                                  "grep, no hand-checked override",
                        "cwe": rec["cwe"]})
        else:
            full = resolve_sha(dirs, rec["fix_commit"])
            if full:
                rec["fix_commit"] = full
    return candidates, log


def main():
    BUILD.mkdir(exist_ok=True)
    candidates, log = mine()
    with (BUILD / "candidates.jsonl").open("w") as fh:
        for c in candidates:
            fh.write(json.dumps(c) + "\n")
    with (BUILD / "funnel_log.jsonl").open("a") as fh:
        for e in log:
            fh.write(json.dumps(e) + "\n")
    short = [c for c in candidates if c["triage"] == "shortlist"]
    print(f"mined={len(candidates)} shortlisted={len(short)} "
          f"resolved={sum(1 for c in short if c['fix_commit'])} "
          f"log_entries={len(log)}")


if __name__ == "__main__":
    main()
