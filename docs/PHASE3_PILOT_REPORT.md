# VulnFix-RL Phase 3 Pilot: Report

Outcome: **the pilot ran end to end.** All three arms (A: base,
B: SFT, C: SFT+GRPO) were trained and evaluated exactly per
PHASE3_PILOT_PLAN.md on the frozen 30-instance dataset, on a
rented Verda H200 instance. Total spend: **USD 21.83 of the
USD 50 cap** (3.03 instance-hours at $6.495/hr, 15:47-18:49 PT,
2026-11-06, through the results handoff; the instance was
terminated by the parent immediately after).

Decision rule (plan Section 5), applied exactly as written:
**no signal / unstable (as measured)** -- precisely, the
"trained arms at or below base" condition: Arm B and Arm C both
score a combined mean reward of 0.0000 against Arm A's 0.0103,
and the mutant-block clause is 0.0 points. GRPO itself did not
diverge (per-step training reward stayed in [0.000, 0.069] with
no instability); the operative reading is **no measurable
held-out training signal under this pilot protocol**.

Per the plan's pre-written branch for this outcome, Phase 4
still proceeds, with the paper's centre of gravity on the
Phase 1-2 result (verification and authoring cost, not
discovery, is the measured bottleneck) and the pilot reported
as a null feasibility result. These numbers are not evidence
for or against SPEC hypotheses H1-H3, in either direction.

This report supersedes the earlier same-day report, which
recorded the blocked RunPod pre-flight; that history is kept
in Section 4 and in pilot/RUN_SHEET.md Steps 0-1.

## 1. Results

Evaluation: frozen verifier, 3 rollouts per task, test (6 tasks,
18 rollouts) and OOD (7 tasks, 21 rollouts), identical settings
for every arm (pilot/configs/eval.yaml). Full per-rollout
records, per-task tables, and the bootstrap are in
build/pilot_results.json.

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

Arm C minus Arm B paired bootstrap (10,000 resamples, task as
unit, descriptive pilot intervals): mean reward difference
0.0000, 95% interval [0.0000, 0.0000] on test, OOD, and
combined -- both arms are identically zero on every task. The
mutant-block bootstrap is undefined (null in the results file):
no task has a measurable mutant rate in both arms, because
mutants are only exercised when a patch applies (Section 2).

Decision-rule clauses (plan Section 5):
- B minus A combined mean reward: -0.0103 (threshold +0.15)
- C minus A combined mean reward: -0.0103 (threshold +0.15)
- C minus B combined mutant block rate: 0.0 points
  (threshold 10 points in either direction)
- signal_present: false

## 2. What the records show mechanically

The dominant fact of the run is diff applicability. Every one
of the 117 eval rollouts produced an extractable diff; almost
none of them apply to the vulnerable snapshot:

| Arm | Diffs that fail `git apply` | Test-tamper (hard zero) | Clean applies |
|---|---|---|---|
| A | 38/39 | 0 | 1 |
| B | 35/39 | 4 | 0 |
| C | 34/39 | 5 | 0 |

The single clean apply in the entire evaluation is one Arm A
rollout on mako-cve-2026-41205, which earned 0.40
(regression 0.25 + minimality 0.15) and blocked nothing -- it
is Arm A's entire nonzero mass. No rollout in any arm blocked
the visible PoC or any mutant, so the exploit components of
the reward were never reached on held-out data: a patch whose
context lines do not match the snapshot exactly scores zero
before the security content of the patch is measured at all.

Arm B's SFT itself trained normally (loss 0.65 -> 0.21 over
the 9 optimizer steps on the 17 gold diffs) and its eval
generations are gold-format diffs, but at temperature 0.7
their hunk context does not reproduce the snapshot exactly
enough to apply. GRPO's training log shows the same constraint
from the other side: over 30 steps and 960 graded training
rollouts, mean reward per step ranged 0.000-0.069 (first-5
average 0.017, last-5 0.031), 80 of 120 prompt groups had zero
reward variance (hence zero advantage and no gradient), and
taxonomy counts were 905 other / 43 test-tamper / 7 pass /
5 deletion. The 7 full passes on train prompts show the reward
is attainable by this policy class on this data; it is simply
rare, and 30 steps at this sparsity did not move held-out
performance off the floor.

Zero grade-errors occurred anywhere in the run (eval grading
and GRPO grading alike): every zero above is a measured zero
from the frozen verifier, not an infrastructure failure.

## 3. Interpretation bounds

- What the pilot establishes: the pipeline runs end to end --
  SFT on gold diffs, GRPO against an executed verifier reward,
  and the frozen evaluation protocol -- on this dataset, at a
  total cost of about $20 of rented GPU. The environment's
  grading path was exercised at scale (960 GRPO grades + 117
  eval grades + a 39/39 gold plumbing re-verification on the
  rented box, mean 1.0, matching the local result).
- What it does not establish: any training signal on held-out
  instances at this scale, in either arm. A null result here
  does not establish that the approach fails; it reflects what
  happened under a small, fixed dataset (17 train) and the
  predefined pilot protocol. In particular the result is
  consistent with the binding constraint being exact-context
  diff applicability rather than the security reasoning the
  reward is designed to measure -- the protocol cannot
  distinguish those, and no post-hoc arm, seed, or schedule
  change was made after results were seen (plan Section 5).
- These numbers are not evidence for or against the
  preregistered hypotheses H1-H3 and must not be cited as such.

## 4. Platform and GPU substitution history

The RunPod route was blocked at pre-flight (account balance
-$0.0516; the one configuration with supply returned "Your
account balance is too low to rent a pod"; the connector
helper's REST creation path is also retired -- full record in
pilot/RUN_SHEET.md Step 1). The Verda route was then attempted
with the user's approval at each step: 1x A100 80GB was
unavailable in all regions and markets; 1x H100 On-Demand
($4.952/hr, approved) sold out in all regions within ~20
minutes; 1x H100 Spot ($2.483/hr, approved) also vanished
before deployment; the user then chose 1x H200 SXM5 141GB
On-Demand at $6.495/hr total (200 GiB disk, FIN-02), deployed
15:47 PT and used for the whole run. The plan's platform
requirement is "a single rented A100-class GPU"; the H200 is
a substitution of capacity class, recorded here and in the
run sheet, with no config or protocol change attached to it.

## 5. Defects found and fixes

All fixes are in pilot/scripts or the environment; the frozen
verifier (src/verifier.py) and the dataset were not modified.
Full detail in pilot/RUN_SHEET.md.

1. Gradient checkpointing was inert (root cause of two Arm B
   OOMs at 45k context): pod_common.load_model never called
   model.train(); from_pretrained leaves the model in eval
   mode and transformers gates the decoder's checkpointing
   branch on self.training. Fixed with model.train() in the
   training branch.
2. Full-vocab float logits in the SFT loss and in GRPO's
   seq_mean_logp (~55 GiB transient at 45k): replaced with
   identical-value forms that apply the LM head only to
   positions the loss actually scores (masked_lm_loss /
   bounded seq_mean_logp).
3. Frozen-verifier record-contract gaps, normalised
   pilot-side in grading.py: the patch_does_not_apply return
   omits "taxonomy" (KeyError killed GRPO step 1 and the first
   A+B report run) and the tamper return leaves "components"
   empty (KeyError in the A+B report run). GRPO restarted from
   step 1 after the fix; the crashed attempt had written no
   checkpoint and consumed no persistent state.
4. Environment (Verda Ubuntu image, not the RunPod image
   pod_bootstrap.sh was written for): the aiohttp grading
   venvs initially bound to the system CPython 3.12.3, whose
   missing headers fail era C-extension builds (multidict);
   rebuilt on uv's managed CPython 3.12.16, as the bootstrap
   intends. Training ran in a dedicated .venv-train
   (torch 2.5.1+cu124, transformers 4.46.3) instead of the
   system python; a Python 3.12 venv as staged, versions
   recorded in the run sheet.

## 6. Spend

| Stage | Item | USD |
|---|---|---|
| Steps 0-1 | local staging; RunPod pre-flight (no pod) | 0.00 |
| Step 2 | Verda H200 instance, run window 15:47-18:49 PT (3.03 h x $6.495) | 19.70 |
| Step 3 | Instance lifetime through console deletion (~18:53 PT), measured as the project balance delta $243.76 -> $221.93 | 2.13 |
| Total | | 21.83 of the 50.00 cap |

Instance-hours are the only spend; the Hugging Face download
and all grading are unbilled. The instance was terminated by
the parent immediately after the 18:49 PT handoff, so the
final billed total is the figure above plus at most a few
minutes.

## 7. What was not established / not done

- No confirmatory claim of any kind (H1-H3 untestable at
  n=17 train / 7 OOD, as the plan states).
- The deferred calibration band decision (Phase 2) is
  untouched; no calibration panel ran in the pilot.
- No checkpoint selection, no extra seeds, no Arm D, no
  schedule extension -- per the plan, none may be added after
  results without an amendment.
- Checkpoints (Arm B and Arm C finals) were run artifacts on
  the rented instance and were not retained after termination;
  all completions, logs, grades, and this report are in the
  local repo (pilot/results/, build/pilot_results.json).
