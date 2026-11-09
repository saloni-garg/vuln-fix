# VulnFix-RL

A trainable reinforcement learning environment for vulnerability
remediation in open-source Python projects, in Prime Intellect
Verifiers format. Given a repository snapshot at a vulnerable commit,
a sanitised vulnerability brief, and one visible proof-of-concept
(PoC) exploit, the agent must produce a source-only patch (a unified
diff) that fixes the vulnerability. Grading is deterministic and
executed: the patch is applied to the snapshot, the visible PoC and a
set of hidden mutant PoCs are run against it, and the repository's own
pinned test suite is checked for regressions. There is no LLM judge
and no human grader.

This is independent defensive-security research. Every vulnerability
is an already-public CVE with a public fix. PoCs run only inside a
local sandbox against the task's own snapshot, never against any
external system. The environment trains and measures patching; it
does not train exploit generation.

The full writeup, with the dataset construction measurements, the
audit history, and the pilot study, is in [WRITEUP.md](WRITEUP.md).
Phase reports and the specification are in [docs/](docs/).

## Why a new dataset: verified gold, not trusted labels

Existing repair benchmarks build on CVEFixes ground truth. SEC-bench
reports that ground truth at only 51% accuracy, because a fixing
commit recorded in a database is not the same thing as a verified
patch. VulnFix-RL therefore treats CVEFixes and GitHub Security
Advisories as mining sources only. An instance enters the dataset
only if every stage of a verification funnel passes, in order:

1. Licence filter (permissive only) and language filter (Python).
2. Environment build: the vulnerable commit installs and its pinned
   test module runs.
3. PoC construction: a PoC succeeds on the vulnerable commit in
   3 of 3 runs.
4. Gold verification: the recorded fix makes the PoC fail in 3 of 3
   runs, and the pinned suite passes with no new failures.
5. Mutant generation: at least 3 mutant PoCs, each succeeding on the
   vulnerable commit and failing on the gold commit.
6. Leak check: the brief and prompts contain no part of the gold
   diff.

The measured cost of that bar is the project's first result: the
funnel verified 11 of 105 mined candidates in Phase 1 (10.5%) and
19 new instances from 272 new candidates in Phase 2 (7.0%). The
binding constraint is per-instance authoring (a working PoC, a
verified gold patch, surviving mutants, a runnable pinned suite, a
licence and leak check per instance), not candidate discovery.

## The verifier

Reward is 1.0 in total, in four components:

| Component | Weight | Rule |
|---|---|---|
| Visible PoC blocked | 0.25 | PoC exits non-zero on the patched snapshot, 3 of 3 runs |
| Hidden mutant PoCs blocked | 0.35 | Prorated over at least 3 pre-freeze mutants never shown to the agent |
| Regression suite | 0.25 | No test that passed on the vulnerable commit fails on the patched commit |
| Minimality and collateral | 0.15 | Full credit only for patches close to the gold patch's file footprint |

A task counts as a pass only at reward 0.85 or above, with both
exploit components at full credit and no tamper flag. Diffs touching
tests, the PoC, CI or build configuration, or dependency manifests
score 0 with a tamper flag. Literal special-casing of the visible
payload zeroes the mutant component.

The verifier is gated by a 10-item degenerate battery (no-op,
deletion, constant return, payload special-case, test tamper,
blacklist, exception swallow, and others, plus the gold patch as a
control). The release gate, applied at the end of both construction
phases, is gold mean reward 1.0 on every verified instance and zero
false passes on the battery. Both phases needed defect fixes to get
there (a battery item that a brief-derived deny-list could pass, and
a regression suite that collapsed silently on one instance); the
failures, fixes, and full re-runs are recorded in the phase reports
in docs/ and in the audit files in build/.

## Dataset (frozen)

30 verified instances, frozen permanently on 2026-11-06:

| CWE family | Verified |
|---|---|
| CWE-22 path traversal | 11 |
| CWE-79 cross-site scripting | 11 |
| CWE-89 SQL injection | 5 |
| CWE-918 server-side request forgery | 2 |
| CWE-78 OS command injection | 1 |
| CWE-502, CWE-611, CWE-94 | 0 |

Splits, frozen by seed 2027 with the record in data/splits/FREEZE.md:
train 17, test 6, OOD 7. Train is repository-disjoint from both
evaluation splits. The OOD split is also CWE-family-disjoint: CWE-89
and CWE-918 are reserved for OOD in full. That reservation carries a
recorded confound: each reserved family maps to a single repository,
so OOD measures family and repository generalisation together.

## Pilot study

The preregistered experiment design (specification, Section 7) was
run as an engineering feasibility pilot on the frozen dataset:
Qwen2.5-Coder-7B-Instruct, Arm A base model, Arm B SFT on the 17
train instances, Arm C SFT then GRPO (30 steps, reward from the
frozen verifier), every arm evaluated on test and OOD with 3 rollouts
per task. The decision rule was written before the run.

Headline result: no measurable training signal at pilot scale.
Combined mean reward was 0.0103 for Arm A, 0.0000 for Arm B, and
0.0000 for Arm C. The mechanism is visible in the grading records:
almost no eval rollout in any arm produced a diff that applies to
the snapshot at all (Arm A: 38 of 39 diffs fail `git apply`; Arm B:
35 of 39, plus 4 test-tamper flags; Arm C: 34 of 39, plus 5). No eval
rollout in any arm blocked a visible PoC or a mutant, so the security
components of the reward were never reached on held-out data. GRPO
training itself was stable (per-step mean reward 0.000 to 0.069 over
960 graded training rollouts, with 7 full passes on train prompts).
Per the pilot plan, these numbers are a feasibility result only;
they are not evidence for or against the preregistered hypotheses,
and a null here does not establish that the approach fails. Total
pilot spend was USD 21.83 of a USD 50 cap. Details:
docs/PHASE3_PILOT_REPORT.md and pilot/RUN_SHEET.md.

## Running the checks

The test suite (verifier unit tests, split rules, calibration
aggregation):

```
python -m pytest tests/ -q -o addopts=
```

The verifier audit (gold patch and degenerate battery over the local
instance packages; requires the repository snapshots, which are
rebuilt from the repo URLs and commits recorded in each
instance.json):

```
python -m src.audit
```

The pilot grading path can be plumbing-checked without a GPU by
grading gold diffs as stand-in rollouts:

```
python pilot/scripts/grade_and_report.py \
  --completions PLUMB=<gold-stand-in completions file> \
  --out build/pilot_plumbing_results.json
```

The shipped build/pilot_plumbing_results.json is that check: 39 of
39 gold stand-ins at reward 1.0 across test, OOD, and combined.

## Repository layout

- `src/` - mining, the verification funnel, snapshot management,
  mutant generation, the verifier, the degenerate battery and audit,
  split generation, and the calibration runner.
- `data/` - the 17 published train-split instance packages (brief,
  PoC, gold patch, instance definition) and `data/splits/` with the
  frozen split files and freeze record for all 30 instances.
- `pilot/` - the Phase 3 pilot: scripts, frozen configs, the train
  prompt exports, and the run sheet.
- `tests/` - the test suite.
- `docs/` - the specification (SPEC_v0.1.md, with its dated
  amendments) and the three phase reports.
- `build/` - the cited results files: both audit gate outputs, the
  pilot results, and the plumbing verification. In the audit and
  plumbing files, mutant payload strings for withheld test and OOD
  instances are replaced by positional labels (mutant_1, mutant_2,
  and so on); exit codes and all metrics are unchanged.
- `WRITEUP.md` - the Phase 4 writeup.

## Publication scope

Train-split instance packages are published in full: brief, visible
PoC, mutant payloads, and gold patch. Test and OOD instance packages
are withheld. Their instance IDs, CWE families, repositories, and
aggregate results are published (in data/splits/, the phase reports,
and the results files in build/), but their briefs, PoCs, mutants,
and gold patches are not, so the evaluation splits stay
uncontaminated for future runs. Snapshots are not embedded in this
repository for any split: each instance.json records the repository
URL and the vulnerable and fix commits, and worktrees are rebuilt
from those.

## Licence

Apache-2.0. See LICENSE. The mined repositories are permissively
licensed; each instance package records its source licence.
