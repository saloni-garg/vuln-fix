"""Tests for the calibration runner plumbing (SPEC Section 8).

These tests stub the verifier and snapshot layers; they test prompt
extraction and aggregation only. The end-to-end plumbing evidence
(gold patch through the real path) is the labelled PLUMBING TEST run
recorded in PHASE2_REPORT.md, not a unit test.
"""
from src import calibration


def test_extract_diff_variants():
    full = "noise\ndiff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
    assert calibration.extract_diff(full).startswith("diff --git")
    bare = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-a\n+b\n"
    assert calibration.extract_diff(bare) == bare
    assert calibration.extract_diff("no diff here") == "no diff here"


def test_gold_standin_is_marked_as_taking_instance():
    assert calibration._takes_inst(calibration.gold_model_fn)
    assert not calibration._takes_inst(lambda prompt: "diff")


def test_run_calibration_aggregation(monkeypatch):
    insts = {
        "i-test": {"instance_id": "i-test"},
        "i-ood": {"instance_id": "i-ood"},
    }
    monkeypatch.setattr(calibration.snapshots, "load_instance",
                        lambda iid: dict(insts[iid]))
    monkeypatch.setattr(calibration, "build_prompt",
                        lambda inst: f"prompt for {inst['instance_id']}")

    def fake_grade(inst, diff):
        base = {"components": {"poc": 0.25, "mutants": 0.35,
                               "regression": 0.25, "minimality": 0.15},
                "tamper": False, "flags": []}
        if inst["instance_id"] == "i-test":
            return {**base, "reward": 1.0, "passed": True,
                    "taxonomy": "pass"}
        return {**base, "reward": 0.4, "passed": False,
                "taxonomy": "no-op"}

    monkeypatch.setattr(calibration.verifier, "grade", fake_grade)
    out = calibration.run_calibration(
        ["i-test", "i-ood"], lambda prompt: "diff --git a/x b/x",
        {"i-test": "test", "i-ood": "ood"}, label="PLUMBING TEST")
    assert out["label"] == "PLUMBING TEST"
    assert out["overall"] == {"n": 2, "mean_reward": 0.7,
                              "pass_rate": 0.5}
    assert out["test"]["mean_reward"] == 1.0
    assert out["ood"]["mean_reward"] == 0.4
    assert out["taxonomy_counts"] == {"pass": 1, "no-op": 1}
