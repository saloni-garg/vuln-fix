"""Split generation and freeze (SPEC Section 6, Phase 2 closure).

Frozen rule, applied deterministically (no randomness; FREEZE_SEED is
recorded in the freeze record for provenance):

1. OOD: every instance whose CWE family is reserved for OOD.
   Reserved families: CWE-89 and CWE-918. Choice and reasoning:
   - Both are the only families whose verified yield maps to a single
     repository each (CWE-89 is all Django, CWE-918 is all PyJWT), so
     reserving them makes OOD disjoint from train by family AND by
     repository at once, which is what SPEC Section 6 requires.
   - Both have crisp PoC oracles and non-trivial yield (5 and 2).
   - CWE-79 (11 instances, 3 repos) and CWE-22 (11 instances, 7 repos)
     are too valuable as training signal to reserve, and reserving
     either would strand same-repo instances of other families.
   - CWE-78 has a single instance in a repo (dulwich) shared with
     CWE-22, so reserving it would strand those instances; CWE-502,
     CWE-611 and CWE-94 have zero verified yield and cannot be
     reserved.
   Confound, stated plainly: because each reserved family is a single
   repo, the OOD split measures family generalisation and repo
   generalisation together; the two cannot be separated with this
   yield. OOD size is whatever the reserved families yield (7).

2. Repo collision: a non-reserved instance whose repository also
   contributes OOD instances (only Django's CWE-22 instances) cannot
   enter train (train must be repo-disjoint from OOD), so it is
   assigned to test and flagged in the freeze record. Documented
   limitation: test and OOD then share the Django repository across
   different families; train shares no repository with either eval
   split, and no reserved family appears outside OOD.

3. Train/test: the remaining instances are grouped by repository and
   whole repositories are assigned to test, smallest first (ties by
   repository URL), adding a repository only while the test count
   stays at or under 25% of the remaining pool; all other remaining
   instances go to train. This keeps train and test repository-
   disjoint and lands the pool at approximately 75/25.

Publication rule (SPEC Section 10, default (a), applies): train-split
PoCs are publishable later; test and OOD gold patches and PoCs are
private and never appear in training files, examples, or docs.
Nothing is published by this module.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import snapshots

FREEZE_SEED = 2027
RESERVED_OOD_FAMILIES = ("CWE-89", "CWE-918")
TEST_FRACTION = 0.25

SPLITS_DIR = snapshots.DATA_DIR / "splits"


def load_verified_instances(data_dir: Path | None = None) -> list[dict]:
    data_dir = data_dir or snapshots.DATA_DIR
    out = []
    for p in sorted(data_dir.iterdir()):
        f = p / "instance.json"
        if p.is_dir() and f.exists():
            d = json.loads(f.read_text())
            out.append({"instance_id": p.name, "cwe": d["cwe"],
                        "repo_url": d["repo_url"],
                        "package": d.get("package")})
    return out


def compute_splits(instances: list[dict]) -> dict[str, list[dict]]:
    """Pure function on [{instance_id, cwe, repo_url}]. Returns
    {split: [record]} where each record gains a 'split' field and,
    for repo-collision test instances, a 'note' field."""
    reserved = set(RESERVED_OOD_FAMILIES)
    ood = [i for i in instances if i["cwe"] in reserved]
    ood_repos = {i["repo_url"] for i in ood}
    rest = [i for i in instances if i["cwe"] not in reserved]
    collision = [i for i in rest if i["repo_url"] in ood_repos]
    pool = [i for i in rest if i["repo_url"] not in ood_repos]

    by_repo: dict[str, list[dict]] = {}
    for i in pool:
        by_repo.setdefault(i["repo_url"], []).append(i)
    target_test = round(TEST_FRACTION * len(pool))
    test_pool: list[dict] = []
    for repo in sorted(by_repo, key=lambda r: (len(by_repo[r]), r)):
        group = by_repo[repo]
        if len(test_pool) + len(group) <= target_test or not test_pool:
            test_pool.extend(group)
    test_ids = {i["instance_id"] for i in test_pool}
    train = [i for i in pool if i["instance_id"] not in test_ids]

    def rec(i, split, note=None):
        r = {"instance_id": i["instance_id"], "cwe": i["cwe"],
             "repo_url": i["repo_url"], "split": split}
        if note:
            r["note"] = note
        return r

    return {
        "train": [rec(i, "train") for i in
                  sorted(train, key=lambda x: x["instance_id"])],
        "test": [rec(i, "test") for i in
                 sorted(test_pool, key=lambda x: x["instance_id"])]
                + [rec(i, "test", "repo_collision_with_ood")
                   for i in sorted(collision,
                                   key=lambda x: x["instance_id"])],
        "ood": [rec(i, "ood") for i in
                sorted(ood, key=lambda x: x["instance_id"])],
    }


def write_splits(splits: dict[str, list[dict]],
                 splits_dir: Path | None = None) -> None:
    splits_dir = splits_dir or SPLITS_DIR
    splits_dir.mkdir(parents=True, exist_ok=True)
    for name, records in splits.items():
        (splits_dir / f"{name}.json").write_text(
            json.dumps(records, indent=2) + "\n")


def load_split_map(splits_dir: Path | None = None) -> dict[str, str]:
    splits_dir = splits_dir or SPLITS_DIR
    out = {}
    for name in ("train", "test", "ood"):
        f = splits_dir / f"{name}.json"
        if f.exists():
            for r in json.loads(f.read_text()):
                out[r["instance_id"]] = name
    return out


def main():
    instances = load_verified_instances()
    splits = compute_splits(instances)
    write_splits(splits)
    for name, records in splits.items():
        print(f"{name}: {len(records)}")
    print("written to", SPLITS_DIR)


if __name__ == "__main__":
    main()
