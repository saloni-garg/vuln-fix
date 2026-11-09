# VulnFix-RL Phase 2 report

Date: 2026-11-06 (closure pass)
Scope: Phase 2 of SPEC_v0.1.md -- dataset scale, split freeze, full
audit at scale, calibration runner. No training, no publishing, no
spend occurred in Phase 2. Spend ledger for the phase: **$0 of the
$80 cap**.

## 1. Dataset outcome

Phase 2 reached **30 verified instances**, not the 200 target. The
binding constraint is funnel-grade per-instance authoring -- every
verified instance needs a working local PoC, a gold patch that
blocks it, at least 3 surviving mutants, a runnable pinned test
suite, a permissive licence, and a clean leak check -- not candidate
supply. The verification bar was not lowered at any point.

Per-family yield. "Mined" is exact (row counts of
`build/phase2/candidates_p2.jsonl`; 366 rows, of which 94 CVEs also
appear in the Phase 1 candidate file and 272 are new). "Verified"
is exact (final `data/*/instance.json` set, cross-checked against
verified entries in `build/funnel_log.jsonl`: exactly the same 30
unique instance ids).

| CWE | Mined (P2 file) | Shortlisted / resolved (P2 only) | Verified new in P2 | Verified total |
|---|---|---|---|---|
| CWE-22 | 111 | not-reconstructed | 4 | 11 |
| CWE-79 | 87 | not-reconstructed | 11 | 11 |
| CWE-89 | 26 | not-reconstructed | 1 | 5 |
| CWE-78 | 34 | not-reconstructed | 1 | 1 |
| CWE-918 | 27 | not-reconstructed | 2 | 2 |
| CWE-502 | 49 | not-reconstructed | 0 | 0 |
| CWE-611 | 8 | not-reconstructed | 0 | 0 |
| CWE-94 | 24 | not-reconstructed | 0 | 0 |
| Total | 366 | not-reconstructed | 19 | 30 |

Why "not-reconstructed": the funnel log (`build/funnel_log.jsonl`,
153 rows across both phases) does not carry a per-phase marker, and
121 of its rows belong to CVEs present in both candidate files, so
Phase-2-only shortlisted/resolved/attempted counts cannot be
separated exactly. They are labelled not-reconstructed rather than
estimated. All-phases figures that are exact from the log: 63
full funnel-run rows covering 31 unique instances (including
re-runs), and final per-candidate discard stages across both
phases of triage 56, resolution 21, deferred 13, poc 9, build 6,
licence 2, gold 1. `build/phase2/mining_errors_p2.jsonl` is empty.

Repository concentration: mistune alone contributes 10 of the 30
instances; django 7; dulwich 3; aiohttp, jinja2, pyjwt 2 each;
bleach, GitPython, mako, setuptools 1 each.

## 2. Split freeze

Frozen 2026-11-06 at the measured scale, replacing the 120/40/40
target proportionally: **train 17 / test 6 / OOD 7**. Files and the
full freeze record (seed 2027, assignment rule, reasoning) are in
`data/splits/` (`train.json`, `test.json`, `ood.json`, `FREEZE.md`);
generation is `src/splits.py`, deterministic.

Reserved OOD families: **CWE-89 and CWE-918** -- the only families
whose yield maps to a single repository each (all-Django, all-PyJWT),
so OOD is disjoint from train by family and by repository.
Confound, recorded in the freeze record: OOD therefore measures
family generalisation and repository generalisation together, and
OOD size is whatever the reserved families yield (7). The two
Django CWE-22 instances sit in test under a documented
repo-collision rule (their repository also contributes OOD
instances, and train shares no repository with either eval split);
test and OOD consequently share the Django repository across
different families. Publication default (a) applies: test/OOD gold
patches and PoCs are private; nothing is published.

## 3. Audit at scale (SPEC Section 8, gate 1)

`src/audit.py` was generalised to take an output filename
(`python3 -m src.audit audit_phase2.json`); gate unchanged: gold
mean 1.0 AND zero battery false passes.

- Run 1 (all 30 instances): gold mean 1.0, gold all pass, battery
  false passes **1**, gate_pass **false**. Archived at
  `build/audit_runs/audit_phase2_20261106T213417.json`.
- Defect: pyjwt-cve-2026-102267 battery item 3 (constant-return)
  scored 1.0. Its gold-overlay test module imports a fix-added
  symbol, so the suite collapses to one collection error on any
  patch not adding the symbol -- identical to its recorded
  baseline -- and the regression component carried no information.
- Fix at the source (verifier, no weight/threshold/battery change):
  regression credit now requires the graded run's suite total to
  reach the instance's recorded `gold_total_tests` (new funnel
  field, backfilled for all 30 from run-1 gold measurements); a
  collapsed suite scores regression 0 and is flagged
  `regression_suite_collapsed`. Single-instance re-check: gold 1.0,
  item 3 at 0.75.
- Run 2 (full re-run): **gold mean 1.0, gold all pass (30/30 at
  1.0), battery false passes 0, gate_pass true** --
  `build/audit_phase2.json`, generated 2026-11-06T21:34Z.

## 4. Calibration (SPEC Section 8, step 2)

Runner built: `src/calibration.py`. Prompt = brief + affected
source file(s) from the vulnerable snapshot; the model returns a
unified diff; the diff is applied and scored by `src/verifier.py`;
aggregation reports mean reward, strict pass rate, test vs OOD
means, and reward-hack taxonomy counts.

Plumbing verified offline: `--mode plumbing` with each instance's
gold patch as the stand-in model output on 3 instances, one per
split (mistune-cve-2026-44708 train, gitpython-cve-2023-41040 test,
django-cve-2025-64459 OOD). All three scored reward 1.0 / passed
through the full prompt -> diff -> grade -> aggregate path, exit
code 0. Output: `build/calibration_plumbing.json`, labelled
PLUMBING TEST throughout. This is plumbing evidence, not panel
data; it says nothing about difficulty.

Panel blocked: the connector's prescribed access check
(`python3 ~/workspace/custom-connectors/custom.anthropic/bin/anthropic_api.py models`)
was re-checked once in this closure pass and returns **HTTP 401
Unauthorized** (exit code 1). Per the standing instruction it was
not retried and no results were simulated. The Section 8 band
decision (target mean reward 0.20-0.60 on test+OOD) is deferred
until panel access exists; no instance was adjusted for difficulty,
because there is no difficulty data.

## 5. Tests

Added in this closure pass: `tests/test_splits.py` (6 tests:
reserved-family rule, single assignment, train repo-disjointness
from test and OOD, repo-collision placement, determinism, frozen
files match the generator on the real 30) and
`tests/test_calibration.py` (3 tests: diff extraction, stand-in
marker, aggregation with stubbed verifier), plus one regression-
credit test in `tests/test_verifier.py`.

Full suite, run in this closure pass:

```
.venv/bin/python -m pytest tests/ -q --no-header -p no:cacheprovider -o addopts=
21 passed in 0.19s   (exit code 0)
```

## 6. Defects found and fixed in this closure pass

1. Phase 2 audit false pass (pyjwt-cve-2026-102267 item 3) --
   verifier regression-collapse fix; see Section 3. Recorded as a
   SPEC amendment dated 2026-11-06.
2. `src/audit.py` hardcoded its Phase 1 output filename and archive
   prefix -- generalised to an output-filename argument with the
   same archiving behaviour.
3. `src/funnel.py` did not record the gold suite total -- it now
   writes `gold_total_tests` for future instances (existing 30
   backfilled from measured gold runs).

## 7. SPEC amendments recorded (all dated 2026-11-06)

Phase 2 mining extension (366 candidates); measured per-family
yield and the unreached 200 target with its binding constraint;
proportional split scaling and the freeze; the Phase 2 audit defect
and verifier fix; the pyjwt-cve-2026-102267 regression-
discrimination limitation; calibration panel blocked with the band
decision deferred.

## 8. Honest limitations

- 30 instances is a prototype-scale dataset. OOD has 7 instances;
  H1's paired-bootstrap interval at that size will be wide, as
  SPEC Section 11 already states.
- CWE-502, CWE-611, and CWE-94 have zero verified yield despite
  49/8/24 mined candidates; the preregistered experiment's OOD
  design rests on the two reserved families only.
- Mistune concentration: 10 of 30 instances (and 10 of 17 training
  instances) come from one repository.
- A GitPython authoring batch designed 12 further candidates and
  produced 0 instances; they are left as resumption leads in the
  funnel records and were not re-authored in this closure pass.
- pyjwt-cve-2026-102267's regression component cannot discriminate
  among patches the way the other 29 instances' can (Section 3 of
  the SPEC amendments); the instance is retained with the
  limitation recorded.
- Phase-2-only funnel stage counts are not reconstructible from
  the logs (Section 1) and are reported as not-reconstructed.
- Carried over from Phase 1, unchanged: graded-run egress control
  is broken-proxy environment variables, not an OS namespace;
  snapshots are not embedded in `data/` (repo URL + commits are
  recorded; worktrees live under `work/snapshots/`); aiohttp
  CVE-2025-69226's oracle is routing-acceptance level; Django
  alias-family PoCs use compile-level oracles.
- No human has reviewed the Phase 2 PoCs or the new code outside
  this build process.
- The calibration panel has never run; there are no difficulty
  numbers for this dataset, and none are claimed anywhere in this
  report.

## 9. Status

Phase 2 is closed at 30 verified instances with frozen splits and a
passed audit gate. Phase 3 (training validation, SPEC Section 7)
is not authorised by anything in this report and waits on a
separate go, a base-model decision, and -- for its calibration
precondition -- panel access that does not currently exist.
