# Split freeze record -- VulnFix-RL Phase 2

Frozen: 2026-11-06 (Phase 2 closure pass)
Freeze seed: 2027 (recorded for provenance; the assignment rule in
`src/splits.py` is deterministic and uses no randomness)
Source pool: the 30 verified instances in `data/` at freeze time.
Files: `train.json` (17), `test.json` (6), `ood.json` (7) in this
directory. The frozen files govern; any change after this date
requires a SPEC amendment and a full battery re-run.

## Reserved OOD families

Reserved entirely for OOD: **CWE-89** and **CWE-918**.

Reasoning: they are the only families whose verified yield maps to a
single repository each (CWE-89 is all Django, CWE-918 is all PyJWT),
so reserving them makes OOD disjoint from train by family and by
repository at once, as SPEC Section 6 requires. CWE-79 and CWE-22
(11 instances each, across 3 and 7 repositories) carry most of the
training signal and reserving either would strand same-repo
instances of other families. CWE-78 has one instance in a repository
(dulwich) shared with CWE-22. CWE-502, CWE-611, and CWE-94 have zero
verified yield and cannot be reserved.

Confound, stated honestly: because each reserved family is a single
repository, OOD measures family generalisation and repository
generalisation together; the two cannot be separated at this yield.
OOD size is whatever the reserved families yield: 7 instances, not
the 40 of the original 120/40/40 target (Phase 2 reached 30 verified
instances in total, not 200; see PHASE2_REPORT.md).

## Assignment rule (src/splits.py, deterministic)

1. All instances of a reserved family go to OOD.
2. Repo collision: a non-reserved instance whose repository also
   contributes OOD instances cannot enter train, so it goes to test
   and is flagged `repo_collision_with_ood` in `test.json`. This
   affects exactly two instances: django-cve-2024-39330 and
   django-cve-2025-59682 (both CWE-22). Documented limitation: test
   and OOD share the Django repository across different families.
   Train shares no repository with either eval split, and no
   reserved family appears outside OOD.
3. Remaining instances are grouped by repository; whole repositories
   are assigned to test, smallest first, only while the test count
   stays at or under 25% of the remaining pool; the rest go to
   train. Train and test are repository-disjoint.

## Per-split, per-family counts

| Split | CWE-22 | CWE-78 | CWE-79 | CWE-89 | CWE-918 | Total |
|---|---|---|---|---|---|---|
| train | 6 | 1 | 10 | 0 | 0 | 17 |
| test | 5 | 0 | 1 | 0 | 0 | 6 |
| ood | 0 | 0 | 0 | 5 | 2 | 7 |

Repositories per split -- train: aiohttp (2), dulwich (3), jinja2
(2), mistune (10). Test: bleach (1), GitPython (1), mako (1),
setuptools (1), django (2, collision only). OOD: django (5),
pyjwt (2).

## Handling rules frozen with the splits

- Test and OOD gold patches and PoCs are private: they never appear
  in training files, examples, or documentation.
- Publication default (a) (SPEC Section 10) applies: train-split
  PoCs are publishable later; test/OOD material is held private.
  Nothing is published by this freeze.
- Evaluation splits are never trained on and never used for model
  selection (SPEC Section 7 protocol).

## Permanent freeze (2026-11-06, Saloni decision)

The dataset is frozen permanently at these 30 verified instances.
Phase 2 does not resume scale-up: measured funnel yield was 11/105 in
Phase 1 and 19 new verified from 272 new candidates in Phase 2, and the
binding constraint is per-instance authoring, not candidate discovery.
The 12 GitPython design leads remain un-authored by decision, recorded
in PHASE2_REPORT.md as future-work leads only. Any future dataset
expansion is a new project phase with its own go, not a continuation
of Phase 2.
