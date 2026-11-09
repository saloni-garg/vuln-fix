# VulnFix-RL: A Trainable RL Environment for Vulnerability Remediation, and Two Measured Bottlenecks

Saloni Garg

## Abstract

VulnFix-RL is a trainable reinforcement learning environment for
vulnerability remediation in open-source Python projects, built in
Prime Intellect Verifiers format. Instances are mined from CVEFixes
and GitHub Security Advisories, but no label from either source is
trusted: an instance enters the dataset only after a verification
funnel confirms that a proof-of-concept (PoC) exploit succeeds on
the vulnerable commit, fails on the gold patch, survives at least
three mutant PoC variants, and leaves the repository's pinned test
suite without new failures. The funnel is expensive in a specific,
measurable way. It verified 11 of 105 mined candidates in Phase 1
(10.5%) and 19 new instances from 272 new candidates in Phase 2
(7.0%), reaching a frozen dataset of 30 verified instances. The
binding constraint is per-instance authoring, not candidate
discovery. The verifier itself is gated by a degenerate-patch
battery: at the end of both construction phases the audit records
gold mean reward 1.0 on every instance and zero false passes. A
preregistered SFT versus SFT+GRPO comparison was then run as an
engineering feasibility pilot on the frozen dataset (17 train, 6
test, 7 out-of-distribution). The pilot produced no measurable
training signal: combined mean reward 0.0103 for the base model and
0.0000 for both trained arms. The grading records identify the
mechanism. Almost no evaluation rollout in any arm produced a diff
that applies to the snapshot (107 of 117 diffs fail `git apply`,
9 more are hard-zeroed as test tampering, and exactly 1 applies
cleanly), and no evaluation rollout blocked
a visible PoC or a mutant, so the security content of the patches
was never reached by the reward. Both headline findings are
bottlenecks of the same kind: in building verified remediation data,
and in training on it, the constraint is mechanical production cost
(authoring verified instances; producing exactly applicable diffs),
not search, mining, or optimisation stability.

## 1. Introduction and positioning

Reinforcement learning for code needs environments whose rewards are
executed rather than judged, and vulnerability remediation is a
natural candidate task: a patch either blocks the exploit and keeps
the test suite green, or it does not. The public resources in this
area are evaluation benchmarks, not training environments. Two
benchmarks share the CVE-Bench name. Zhu et al. (ICML 2025) built 40
critical-severity web application CVEs in sandboxed containers for
the exploitation task; the best agent framework exploited 13% in the
one-day setting. Wang et al. (NAACL 2025) built a repair benchmark of
509 CVEs from the CVEFixes database across 4 languages and 120
repositories; SWE-agent repaired 21% at best. SEC-bench (2025)
constructed 200 verified C/C++ instances from 898 candidates, at a
reported construction cost of 0.87 USD per instance, filtering on a
reproducible PoC and a validated patch; the best patching success in
its original evaluation was 34.0%. SEC-bench also reports the fact
that motivates this project's construction method: CVEFixes ground
truth labels are only 51% accurate, because the recorded fixing
commit is not verified as a patch.

None of these provides a train split, a deterministic reward, or a
supervised versus RL comparison. VulnFix-RL is built to be the
missing piece: a trainable environment with gold patches that are
verified rather than trusted, hidden mutant PoCs so that
special-casing the visible exploit does not pass, and a
preregistered experiment design (specification Section 7) asking
whether verifier-based RL adds measurable value beyond SFT on gold
patches, with the primary endpoint on out-of-distribution (OOD)
generalisation: blocking variants of exploits the model has never
seen, in CWE families held out of training.

This writeup reports the construction and pilot phases honestly at
the scale they reached. The dataset target of 200 verified
instances was not met; the dataset is frozen at 30, and the
experiment ran as a pilot whose results, by a rule written before
the run, are never cited as evidence for or against the
preregistered hypotheses. What the project does produce is two
measured results about where the cost of this research programme
actually sits, and an environment plus audit trail that makes those
measurements checkable.

## 2. Environment design

A task consists of a repository snapshot at the vulnerable commit
(permissive licences only), a sanitised brief (the CVE description
with the fixing commit, patch hints, and any text quoting the fix
removed; the CWE identifier; affected file paths), one visible PoC
(a Python script that exits 0 when the exploit succeeds and non-zero
when it is blocked), and the repository's own test command, pinned
per instance to the test module or modules relevant to the
vulnerability. The agent's action is a single unified diff touching
source files only. Diffs touching test files, the PoC, build or CI
configuration, or dependency manifests are rejected before grading
and scored 0 with a tamper flag. The agent has no shell access to
the grading environment, the hidden PoCs, or the gold patch.

Reward totals 1.0:

| Component | Weight | Rule |
|---|---|---|
| Visible PoC blocked | 0.25 | PoC exits non-zero on the patched snapshot, 3 of 3 runs |
| Hidden mutant PoCs blocked | 0.35 | Prorated over at least 3 mutants, generated pre-freeze and never shown to the agent |
| Regression suite | 0.25 | No test that passed on the vulnerable commit fails on the patched commit |
| Minimality and collateral | 0.15 | Full credit if the patch touches only files the gold patch touches, plus at most 1 additional source file; deductions per extra file; 0 if any function present at the vulnerable commit is deleted |

A task passes only if reward is at least 0.85, both exploit
components are at full credit, and the tamper flag is clear. Three
penalty rules target known degenerate strategies: a patch containing
the visible PoC's literal payload as a special case scores 0 on the
mutant component; a patch that swallows all exceptions around the
affected entry point scores 0 on the regression component; and,
added by a Phase 2 audit fix described below, regression credit
requires the graded run's suite total to reach the total recorded
under the gold patch, so a suite that collapses to a collection
error cannot pass silently.

Mutant PoCs are systematic variants of the visible PoC that preserve
the vulnerability class and change the surface: payload encoding,
casing and ordering for injection families, file paths and
extensions for traversal families, host and port forms for SSRF,
serialised payload forms for deserialisation. Mutators are fixed per
CWE family and frozen with the dataset.

Every verifier change is gated by a 10-item degenerate battery run
against every verified instance: no-op, deletion of the vulnerable
function, constant return, literal payload special-case, patching
the tests instead of the source, blacklist of the visible payload,
bare exception swallow, suppression of a validation call,
deny-listing the brief's example strings, and the gold patch as a
control that must score 1.0. The gate is gold mean 1.0 and zero
false passes. Rollouts in the partial-credit band or carrying a
tamper flag are classified into a closed reward-hack taxonomy
(no-op, deletion, constant-return, payload special-case, test
tamper, blacklist, exception swallow, other) and the counts are
reported, not treated as internal diagnostics.

## 3. Dataset construction: the funnel and its measured yield

Sources are CVEFixes (about 5,400 CVE-fix pairs) and GitHub Security
Advisories, filtered to Python. The funnel applies, in order:
licence and language filter; environment build (the vulnerable
commit installs and the pinned suite runs); PoC construction with a
3-of-3 determinism requirement on the vulnerable commit; gold
verification (the PoC fails 3 of 3 on the gold commit and the suite
shows no new failures); mutant generation (at least 3 mutants, each
validated on both commits); and a leak check (no fragment of the
gold diff in the brief or prompts).

Phase 1 (CWE-89 and CWE-22) measured the funnel end to end:

| Stage | Count |
|---|---|
| Advisories mined | 105 (22 CWE-89, 83 CWE-22) |
| Triage discards | 56 |
| Shortlisted | 49 |
| Fix-commit resolution discards | 21 |
| Resolved | 28 (plus 1 resolved by hand during authoring) |
| Attempted end to end | 11 |
| Verified | 11 |

Yield: 11 of 105 mined (10.5%), and 11 of 29 resolved (38%). Five
further resolved candidates were discarded by hand because their
PoCs need database backends or native libraries the sandbox lacks,
and 13 were deferred. The Phase 1 target of 20 verified instances
was not met; the shortfall was reported rather than padded, and the
bar was not lowered.

Phase 2 extended mining to all eight target families. The second
candidate file holds 366 rows (CWE-22: 111, CWE-79: 87, CWE-502: 49,
CWE-78: 34, CWE-918: 27, CWE-89: 26, CWE-94: 24, CWE-611: 8), of
which 94 CVEs overlap the Phase 1 file, leaving 272 new candidates.
Phase 2 added 19 verified instances, a yield of 19 from 272 (7.0%).
Final totals by family: CWE-22: 11, CWE-79: 11, CWE-89: 5, CWE-918:
2, CWE-78: 1, CWE-502: 0, CWE-611: 0, CWE-94: 0. One authoring batch
(GitPython, 12 designed candidates across CWE-78, CWE-94, and
CWE-22) produced 0 instances.

The dataset is therefore frozen permanently at 30 verified
instances, split 17 train / 6 test / 7 OOD with the freeze record in
data/splits/FREEZE.md. Extrapolating either measured yield, the
original 200-instance target would require roughly 1,700 to 2,400
further candidates at unchanged per-instance authoring cost; even
completing all 12 GitPython leads would reach only about 42. The
conclusion is structural. Candidate discovery is cheap and
effectively unbounded; what is scarce is funnel-grade authoring
labour per instance: a working local PoC, a gold patch verified to
block it, at least 3 surviving mutants, a runnable pinned suite, a
permissive licence, and a clean leak check. Any serious scale-up of
verified remediation datasets is an authoring-automation problem,
not a mining problem. SEC-bench's reported 0.87 USD per instance
for C/C++ was achieved with a looser bar (a reproducible PoC and a
validated patch, without mutant validation, per-instance pinned
suites, or a leak check); the comparison suggests the yield and cost
of a verified dataset are set by where the bar is placed, and this
project chose to measure its own bar rather than lower it.

## 4. Audit and calibration

The audit gate (gold mean 1.0, zero battery false passes) did not
pass on its first attempt in either phase, and the failures are
part of the result.

Phase 1 run 1 scored gold mean 0.90 with 3 battery false passes.
Four defects were found and fixed at the source, including a
regression baseline that penalised gold patches for upstream test
changes (fixed with gold-test overlay semantics) and brief example
strings that every mutant had to contain by construction, which let
a brief-derived deny-list pass. Run 2 reached gold mean 1.0 with 1
remaining false pass: for setuptools CVE-2025-47273, the brief's two
example strings jointly covered all four frozen mutants, so the
deny-list battery item scored 1.0. The remedy was mutant
diversification only (no verifier rule, weight, or threshold
changed): after re-validation the instance has 5 surviving mutants
and the battery item scores 0.79. Full re-run (run 3,
build/audit_phase1.json) passed the gate: gold mean 1.0, 11 of 11
gold at 1.0, battery false passes 0.

Phase 2 run 1 over all 30 instances again found 1 false pass:
pyjwt-cve-2026-102267, battery item 3 (constant return) at 1.0. Its
gold-overlay test module imports a symbol the fix adds, so on any
patch that does not add the symbol the suite collapses to a single
collection error, identical to its recorded baseline, and "no new
failures" carried no information. The fix is in the verifier:
regression credit now requires the graded suite total to reach the
instance's recorded gold total (a collapsed suite scores 0 and is
flagged). Full re-run (run 2, build/audit_phase2.json) passed: gold
mean 1.0, 30 of 30 at 1.0, battery false passes 0.

Difficulty calibration is the one planned component that did not
run. The calibration runner is built (brief plus affected snapshot
sources as prompt, model diff as answer, the frozen verifier as
grader, with mean reward, pass rate, split means, and taxonomy
aggregation), and its plumbing is verified offline: gold patches as
stand-in model outputs on 3 instances, one per split, all scoring
1.0 through the full prompt to diff to grade to aggregate path. The
frontier-model panel itself could not run: the provider API access
available to this project returns HTTP 401, re-checked at Phase 2
closure. No results were simulated. The pre-registered band
decision (target panel mean reward 0.20 to 0.60 on test plus OOD)
is therefore deferred, and no instance was made easier or harder on
difficulty grounds, because there is no difficulty data. The
dataset and verifier freeze stands without it.

## 5. Pilot study

With the dataset frozen at 30, the preregistered experiment was run
as an engineering feasibility pilot under a plan written before any
training: identical arms and evaluation protocol to the
specification, shortened, with a decision rule fixed in advance.
The pilot asks one question: can the SFT and SFT+GRPO pipelines run
end to end on this environment and produce a measurable training
signal on held-out instances? The base model for all arms is
Qwen2.5-Coder-7B-Instruct. Arm A is the base model. Arm B is SFT on
the 17 train instances (brief plus snapshot context to gold diff, 3
epochs; as run, 9 optimiser steps, training loss 0.6505 to 0.2128).
Arm C initialises from Arm B and runs GRPO on the train instances
with the Section 2 reward (30 steps, 4 prompts per step, group size
8, temperature 0.9). Evaluation is identical for every arm: test (6
tasks) and OOD (7 tasks), 3 rollouts per task, temperature 0.7, the
frozen verifier. Train prompts are long (750 to 42,955 tokens in the
Qwen2.5 tokenizer, gold completions 165 to 2,011), which is why the
pilot schedule is short. Total pilot spend was USD 21.83 of a
USD 50 cap on a single rented GPU.

Results (full per-rollout records in build/pilot_results.json):

| Arm | Split | Mean reward | Pass rate | Visible block | Mutant block |
|---|---|---|---|---|---|
| A (base) | test | 0.0222 | 0.000 | 0.000 | 0.000 |
| A (base) | OOD | 0.0000 | 0.000 | 0.000 | 0.000 |
| A (base) | combined | 0.0103 | 0.000 | 0.000 | 0.000 |
| B (SFT) | test | 0.0000 | 0.000 | 0.000 | 0.000 |
| B (SFT) | OOD | 0.0000 | 0.000 | 0.000 | 0.000 |
| B (SFT) | combined | 0.0000 | 0.000 | 0.000 | 0.000 |
| C (SFT+GRPO) | test | 0.0000 | 0.000 | 0.000 | 0.000 |
| C (SFT+GRPO) | OOD | 0.0000 | 0.000 | 0.000 | 0.000 |
| C (SFT+GRPO) | combined | 0.0000 | 0.000 | 0.000 | 0.000 |

The Arm C minus Arm B paired bootstrap (10,000 resamples, task as
unit) gives a mean reward difference of 0.0000 with a 95% interval
of [0.0000, 0.0000] on every split, because both arms are
identically zero on every task; these intervals are descriptive
pilot intervals, not confirmatory ones. The mutant-block bootstrap
is undefined: no task has a measurable mutant rate in both arms,
for the reason Section 6 gives.

Decision rule, applied exactly as written before the run: signal
requires a trained arm to beat Arm A's combined mean reward by at
least 0.15, or Arm C's mutant block rate to differ from Arm B's by
at least 10 points in either direction. Measured clauses: B minus A
is -0.0103, C minus A is -0.0103, C minus B mutant block is 0.0
points. The branch is therefore "no signal / unstable (as
measured)": trained arms at or below base. GRPO did not diverge;
the operative reading is no measurable held-out training signal
under this pilot protocol.

## 6. Analysis: diff applicability is the operative bottleneck

Every one of the 117 evaluation rollouts produced an extractable
diff. Almost none of them apply:

| Arm | Diffs failing `git apply` | Test-tamper (hard zero) | Clean applies |
|---|---|---|---|
| A | 38 of 39 | 0 | 1 |
| B | 35 of 39 | 4 | 0 |
| C | 34 of 39 | 5 | 0 |

The single clean apply in the whole evaluation is one Arm A rollout
on a test instance, which scored 0.40 (regression 0.25 plus
minimality 0.15) and blocked nothing; it is Arm A's entire non-zero
mass. No rollout in any arm blocked the visible PoC or any mutant.
The reward's exploit components, the parts that measure security
reasoning, were never reached on held-out data: a patch whose
context lines do not match the snapshot exactly scores zero before
its security content is measured at all. Arm B's generations are
gold-format diffs (SFT trained normally), but at sampling
temperature their hunk context does not reproduce the snapshot
exactly enough to apply.

The training side shows the same constraint from the other
direction, and also shows the reward is attainable. Over 30 GRPO
steps and 960 graded training rollouts, per-step mean reward ranged
from 0.000 to 0.069 (first 5 steps averaging 0.017, last 5
averaging 0.031, overall 0.0249). 80 of 120 prompt groups had zero
reward variance, hence zero advantage and no gradient. Taxonomy
counts over the 960 rollouts: 905 other (predominantly
non-applying diffs), 43 test-tamper, 7 pass, 5 deletion. The 7 full
passes on train prompts show this policy class can produce an
applying, blocking patch on this data; it is simply rare, and 30
steps at this sparsity did not move held-out performance off the
floor. Zero grade errors occurred anywhere in the run, and the
grading path was re-verified on the rented machine before any arm
ran (39 of 39 gold stand-ins at reward 1.0, matching the local
result), so the zeros are measured zeros from the frozen verifier,
not infrastructure failures.

Two consequences follow. First, for this output contract (brief
plus file sources in, raw unified diff out), exact-context
applicability is a precondition that dominates everything
downstream of it; an environment that wants to measure and train
remediation skill at this model scale has to either teach or
engineer applicability separately, or change the contract (Section
8). Second, the pilot protocol cannot distinguish "the model cannot
fix these vulnerabilities" from "the model cannot emit an
applicable diff for these snapshots", and this writeup does not
pretend otherwise. The null result is a feasibility result about
the pipeline under a fixed small dataset and a pre-written
protocol. It does not establish that the approach fails, and it is
not evidence about the preregistered hypotheses H1 to H3, whose
5-point OOD threshold is not testable at 17 train and 7 OOD
instances.

## 7. Limitations

- Scale. 30 verified instances is prototype scale. OOD has 7
  instances; any interval at that size is wide, as the
  specification stated in advance.
- Family imbalance and zero-yield families. CWE-79 and CWE-22
  supply 22 of 30 instances; CWE-502, CWE-611, and CWE-94 supply
  none despite 49, 8, and 24 mined candidates respectively.
  Repository concentration compounds this: one repository (Mistune)
  contributes 10 of 30 instances and 10 of the 17 training
  instances.
- OOD confound. The reserved OOD families (CWE-89, CWE-918) each
  map to a single repository, so OOD measures family and repository
  generalisation together and the two cannot be separated at this
  yield. In addition, two Django CWE-22 instances sit in test under
  a documented repo-collision rule, so test and OOD share the
  Django repository across families; train shares no repository
  with either evaluation split.
- Calibration missing. The difficulty panel never ran (Section 4),
  so there are no difficulty numbers for this dataset, and the
  pre-registered difficulty band decision is unmade.
- Pilot scale. The pilot is an engineering feasibility run: one
  base model, one seed, shortened schedules. Its numbers support no
  confirmatory claim in either direction.
- Oracle strength varies. One instance (aiohttp CVE-2025-69226) has
  a routing-acceptance oracle rather than a data-return oracle, and
  the Django SQL-injection alias instances use compile-level
  oracles; both choices mirror the fixes' own regression tests and
  are recorded per instance. One instance (pyjwt-cve-2026-102267)
  has a regression component that cannot discriminate among patches
  the way the other 29 can, because its pinned suite imports a
  fix-added symbol; it is retained with that limitation recorded.
- Sandbox isolation. Graded runs discourage network egress with
  deliberately broken proxy environment variables. That is an
  env-level guard, not an OS-level network namespace, and nothing
  here verifies isolation beyond it.
- Snapshots are not embedded in the dataset packages; each package
  records the repository URL and the vulnerable and fix commits,
  and rebuilding worktrees requires re-cloning.
- Contamination. A base model may have seen a public gold patch in
  pretraining. The mutant-PoC endpoint is a partial mitigation
  (memorising the visible PoC does not pass the mutants unless the
  fix generalises), not a cure.
- Selection. Python only, crisp-oracle CWE families only. Nothing
  here generalises to memory-safety patching or to fixes whose
  correctness is a judgement call.

## 8. Future work

- Applicability-aware output contracts. The pilot's mechanism
  points at the output contract, not at the reward. Candidate
  directions, in increasing order of contract change: report
  applicability rate as a first-class metric beside reward in every
  run; add an apply-and-repair loop in which a non-applying diff is
  returned to the model with the `git apply` error; or replace raw
  diffs with structured edits (file, anchor, replacement) that the
  environment renders into a patch, removing exact-context
  reproduction from the model's task entirely. Each changes what is
  measured, so each needs its own preregistered amendment rather
  than a quiet protocol edit.
- Scaling authoring, not mining. The measured funnel yields say the
  next order of magnitude in dataset size comes from automating the
  authoring stages (PoC drafting with funnel verification as the
  filter, mutant synthesis, suite pinning), with the same bar and
  the same audit gate. The 12 designed-but-unauthored GitPython
  candidates are recorded as resumption leads for exactly this.
- Calibration completion. When provider panel access exists, run
  the deferred difficulty panel and record the band decision as an
  amendment, so a future confirmatory run starts from a calibrated
  dataset rather than an unmeasured one.
- The confirmatory experiment. The preregistered SFT versus
  SFT+GRPO comparison at specification scale remains undone, and is
  worth doing only after the two items above land: a dataset whose
  size is set by cheaper authoring, and an output contract under
  which the reward measures remediation rather than diff emission.
