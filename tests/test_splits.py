"""Tests for split generation (SPEC Section 6, Phase 2 freeze)."""
import pytest

from src import splits


def _inst(iid, cwe, repo):
    return {"instance_id": iid, "cwe": cwe, "repo_url": repo}


SYNTHETIC = [
    _inst("a1", "CWE-89", "https://x/repoA.git"),
    _inst("a2", "CWE-89", "https://x/repoA.git"),
    _inst("b1", "CWE-918", "https://x/repoB.git"),
    # repoA also has a non-reserved instance: repo collision with OOD
    _inst("a3", "CWE-22", "https://x/repoA.git"),
    _inst("c1", "CWE-22", "https://x/repoC.git"),
    _inst("d1", "CWE-79", "https://x/repoD.git"),
    _inst("d2", "CWE-79", "https://x/repoD.git"),
    _inst("e1", "CWE-79", "https://x/repoE.git"),
    _inst("f1", "CWE-22", "https://x/repoF.git"),
    _inst("g1", "CWE-78", "https://x/repoG.git"),
]


def _by_split(s):
    return {name: {r["instance_id"] for r in recs}
            for name, recs in s.items()}


def test_reserved_families_only_in_ood():
    s = splits.compute_splits(SYNTHETIC)
    ids = _by_split(s)
    assert ids["ood"] == {"a1", "a2", "b1"}
    for split in ("train", "test"):
        for r in s[split]:
            assert r["cwe"] not in splits.RESERVED_OOD_FAMILIES


def test_every_instance_assigned_exactly_once():
    s = splits.compute_splits(SYNTHETIC)
    all_ids = [r["instance_id"] for recs in s.values() for r in recs]
    assert sorted(all_ids) == sorted(i["instance_id"]
                                     for i in SYNTHETIC)


def test_train_repo_disjoint_from_test_and_ood():
    s = splits.compute_splits(SYNTHETIC)
    repos = {name: {r["repo_url"] for r in recs}
             for name, recs in s.items()}
    assert not (repos["train"] & repos["test"])
    assert not (repos["train"] & repos["ood"])


def test_repo_collision_instance_goes_to_test_with_note():
    s = splits.compute_splits(SYNTHETIC)
    test = {r["instance_id"]: r for r in s["test"]}
    assert "a3" in test
    assert test["a3"].get("note") == "repo_collision_with_ood"
    assert all(r["instance_id"] != "a3" for r in s["train"])


def test_deterministic():
    assert splits.compute_splits(SYNTHETIC) == \
        splits.compute_splits(SYNTHETIC)


def test_frozen_files_match_generator_on_real_data():
    instances = splits.load_verified_instances()
    if len(instances) != 30:
        pytest.skip("needs the full 30-instance pool; this checkout "
                    "publishes the train split only")
    assert len(instances) == 30
    expected = splits.compute_splits(instances)
    frozen = {}
    for name in ("train", "test", "ood"):
        import json
        frozen[name] = json.loads(
            (splits.SPLITS_DIR / f"{name}.json").read_text())
    assert frozen == expected
    assert len(frozen["train"]) == 17
    assert len(frozen["test"]) == 6
    assert len(frozen["ood"]) == 7
