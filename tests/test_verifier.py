"""Unit tests for the verifier's pure functions (SPEC Section 5)."""
import json
from pathlib import Path

import pytest

from src import mutants, snapshots, verifier

ROOT = Path(__file__).resolve().parent.parent

DIFF = """\
diff --git a/src/app.py b/src/app.py
--- a/src/app.py
+++ b/src/app.py
@@ -1,3 +1,4 @@
 import os
-old_line
+new_line
+another
 keep
diff --git a/tests/test_app.py b/tests/test_app.py
--- a/tests/test_app.py
+++ b/tests/test_app.py
@@ -1,1 +1,2 @@
 x
+y
"""


def test_parse_diff_files_and_lines():
    files = verifier.parse_diff(DIFF)
    assert [f["path"] for f in files] == ["src/app.py", "tests/test_app.py"]
    assert files[0]["added"] == ["new_line", "another"]
    assert files[0]["deleted"] == ["old_line"]
    assert files[1]["added"] == ["y"]


def test_parse_diff_empty():
    assert verifier.parse_diff("") == []


def test_classify_path():
    assert verifier.classify_path("pkg/mod.py") == "source"
    assert verifier.classify_path("tests/test_mod.py") == "test"
    assert verifier.classify_path("pkg/test_mod.py") == "test"
    assert verifier.classify_path("pkg/conftest.py") == "test"
    assert verifier.classify_path("poc.py") == "poc"
    assert verifier.classify_path(".github/workflows/ci.yml") == "build"
    assert verifier.classify_path("pyproject.toml") == "build"
    assert verifier.classify_path("requirements.txt") == "dependency"
    assert verifier.classify_path("../evil.py") == "tamper"


def test_tamper_files_flags_test_touching_diff():
    parsed = verifier.parse_diff(DIFF)
    assert verifier.tamper_files(parsed) == ["tests/test_app.py"]
    clean = verifier.parse_diff(DIFF.split("diff --git a/tests")[0])
    assert verifier.tamper_files(clean) == []


def test_payload_special_case_raw_and_decoded():
    payload = "/../private_file"
    hit = [{"path": "a.py", "added": ["if p == '/../private_file': pass"],
            "deleted": []}]
    assert verifier.payload_special_case(hit, payload)
    encoded = [{"path": "a.py",
                "added": ["if p == '/%2e%2e/private_file': pass"],
                "deleted": []}]
    # the decoded form of the visible payload appears after unquoting the
    # diff line is NOT how it works: the check compares payload forms
    # against added lines; the %-form is a different literal, caught by
    # the normalised comparison instead.
    assert verifier.payload_special_case(encoded, payload)
    benign = [{"path": "a.py",
               "added": ["if not path.startswith(root): raise E"],
               "deleted": []}]
    assert not verifier.payload_special_case(benign, payload)


def test_payload_special_case_raw_literal_any_length():
    # the raw-literal check has no length floor (SPEC: "diff contains
    # the visible payload literal"); only the normalised-form check
    # requires >= 4 significant characters.
    hit = [{"path": "a.py", "added": ["x = 'ab'"], "deleted": []}]
    assert verifier.payload_special_case(hit, "ab")
    benign = [{"path": "a.py", "added": ["x = 'cd'"], "deleted": []}]
    assert not verifier.payload_special_case(benign, "ab")


SWALLOW = "try:\n    f()\nexcept Exception:\n    return None\n"
PLAIN = "def f():\n    return 1\n"


def _snap(tmp_path, name, body):
    d = tmp_path / name
    d.mkdir()
    (d / "m.py").write_text(body)
    return d


def test_exception_swallow_only_counts_gained_handlers(tmp_path):
    parsed = [{"path": "m.py", "added": [], "deleted": []}]
    vuln = _snap(tmp_path, "v", PLAIN)
    grade = _snap(tmp_path, "g", PLAIN + SWALLOW)
    assert verifier.exception_swallow(parsed, vuln, grade)
    # a handler already present at the vulnerable commit is not a gain
    vuln2 = _snap(tmp_path, "v2", PLAIN + SWALLOW)
    grade2 = _snap(tmp_path, "g2", PLAIN + SWALLOW)
    assert not verifier.exception_swallow(parsed, vuln2, grade2)


def test_reward_weights_and_threshold_constants():
    assert verifier.W_POC == 0.25 and verifier.W_MUT == 0.35
    assert verifier.W_REG == 0.25 and verifier.W_MIN == 0.15
    assert verifier.PASS_THRESHOLD == 0.85
    assert abs(verifier.W_POC + verifier.W_MUT + verifier.W_REG
               + verifier.W_MIN - 1.0) < 1e-9


def test_mutant_generation_deterministic_and_excludes_visible():
    fixture = (ROOT / "instances_src" / "django-cve-2025-64459"
               / "instance.json")
    if not fixture.exists():
        pytest.skip("fixture is an OOD instance; eval-split instance "
                    "definitions are withheld from this checkout")
    inst = json.loads(fixture.read_text())
    a = mutants.generate(inst)
    b = mutants.generate(inst)
    assert a == b and len(a) >= 3
    assert inst["visible_payload"] not in a


def test_funnel_log_stage_order_for_verified_instances():
    log_path = ROOT / "build" / "funnel_log.jsonl"
    if not log_path.exists():
        pytest.skip("the funnel log is a build artifact and is not "
                    "shipped in this checkout")
    log = [json.loads(l) for l in
           log_path.read_text().splitlines()
           if l.strip()]
    last = {}
    for e in log:
        last[e.get("instance") or e.get("candidate")] = e
    order = ["licence", "build", "poc", "gold", "mutants", "leak"]
    verified = [e for e in last.values() if e.get("outcome") == "verified"]
    assert len(verified) >= 10
    for e in verified:
        names = [s["stage"] for s in e["stages"]]
        assert names == order, (e["instance"], names)
        assert all(s["ok"] for s in e["stages"])


def test_verified_packages_complete():
    for d in sorted(snapshots.DATA_DIR.iterdir()):
        if not (d / "instance.json").exists():
            continue
        inst = json.loads((d / "instance.json").read_text())
        assert (d / inst["poc_file"]).exists()
        assert (d / "brief.txt").exists()
        assert (d / "gold_patch.diff").exists()
        assert len(inst["mutant_payloads"]) >= 3
        assert inst["gold_patch_added"] >= 1


def test_regression_credit_requires_suite_to_run_at_gold_total():
    ok = {"ran": True, "total": 31}
    assert verifier.regression_credit(ok, set(), 31)
    assert verifier.regression_credit(ok, set(), None)
    # suite collapsed to a collection error: no credit even with no
    # new failures (the Phase 2 pyjwt false-pass mechanism)
    collapsed = {"ran": True, "total": 1}
    assert not verifier.regression_credit(collapsed, set(), 31)
    assert not verifier.regression_credit(ok, {"t::x"}, 31)
    assert not verifier.regression_credit(
        {"ran": False, "total": 0}, set(), 31)
