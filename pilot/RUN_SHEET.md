# VulnFix-RL Phase 3 Pilot: Run Sheet

Pilot plan: PHASE3_PILOT_PLAN.md (arms, protocol, decision rule
fixed before launch). Hard spend cap: USD 50 total (GPU rental plus
any inference). Dataset: permanent Phase 2 freeze (train 17 /
test 6 / OOD 7). Verifier: frozen Phase 2 version, unmodified.

## Step 0 -- local staging (2026-11-06, $0)

Commands run from the repository root unless noted.

- Data export: `python pilot/scripts/build_data.py` with the
  Qwen2.5 tokenizer (tokenizer.json fetched from the model repo)
  - pilot/data/sft_train.jsonl: 17 rows (train split only; prompt =
    src/calibration.build_prompt, completion = gold diff)
  - pilot/data/grpo_train.jsonl: 17 rows (train prompts only)
  - pilot/data/eval_tasks.jsonl: 13 rows (6 test then 7 OOD, freeze
    order)
  - pilot/data/lengths.json: prompt tokens min 750 / max 42955;
    gold completion tokens min 165 / max 2011 (Qwen2.5 tokenizer,
    vocab 151643, tokenizer.json fetched from the model repo)
- Configs committed before launch: pilot/configs/sft.yaml,
  pilot/configs/grpo.yaml, pilot/configs/eval.yaml. Model for all
  arms: Qwen/Qwen2.5-Coder-7B-Instruct.
  - Staging decision (recorded in the configs): the shipped model
    config caps positions at 32768, below the longest prompts
    (max 42955). All arms load with YaRN rope scaling (factor 4,
    original_max_position_embeddings 32768), identically for train
    and eval. Prompts are never truncated; the SFT script asserts
    max_seq_len 46080 covers the longest example (44966) and fails
    loudly otherwise.
  - GRPO prompts_per_step is 4 (reason recorded in grpo.yaml: the
    reward is an executed grading, and train prompts run to 42955
    tokens). Steps 30, group 8, temperature 0.9, lr 1e-6, KL beta 0.
  - Eval: 3 rollouts/task, temperature 0.7, top_p 1.0, seed 17
    (reset per task as seed + task index, same for every arm).
- Scripts: pilot/scripts/build_data.py, train_sft.py, train_grpo.py,
  evaluate.py, grade_and_report.py, grading.py (parallel grading,
  grouped per instance, spawn pool), pod_common.py (one prompt /
  model-loading contract for all arms).
  All scripts pass py_compile under the project venv.
- Plumbing test of the eval file flow (local, $0):
  gold diffs written as 39 PLUMB-arm rollouts (3 per eval task) and
  graded with `pilot/scripts/grade_and_report.py --workers 4`.
  The first attempt failed in aggregation with KeyError
  'instance_id': grade_and_report.py did not copy the id into the
  verifier records it enriches (the verifier returns it under
  'instance'). One-line fix in grade_and_report.py only -- the
  frozen verifier and dataset were not touched -- and the re-run
  completed: build/pilot_plumbing_results.json -- mean reward 1.0,
  pass rate 1.0, visible and mutant block rates 1.0 on test, OOD,
  and combined (39/39 records at reward 1.0, 13 per-task entries).
  This verifies the completions -> grade -> metrics path only;
  it is not pilot data.

## Step 1 -- GPU pre-flight (2026-11-06)

- RunPod route: the connector helper
  (the runpod connector helper (runpod_api.py))
  now authenticates (the 2026-11-01 placeholder-key 401 no longer
  applies; the registered credential works).
  - `balance`: clientBalance -0.0516 USD, spendLimit 80.
  - `pods`: none.
  - `gpu-types`: NVIDIA A100 80GB PCIe and A100-SXM4-80GB listed.
  - Open question the balance raises: whether pod creation succeeds
    on a ~zero balance is decided by attempting creation (below);
    RunPod historically requires prepaid balance, in which case the
    blocker is an account top-up through the RunPod web UI, which is
    outside this run's authority and tooling.
- Verda route: no connector exists for Verda in this environment
  (connector search, 2026-11-06: no matches). The CVPR-pilot Verda
  access was through a saved browser login; browser flows are not
  available to this run, and there is no Verda API/CLI route
  configured. Verda is therefore not a usable route for this pilot.

### Creation attempts (2026-11-06, all via the connector auth path)

1. Connector helper REST create (rest.runpod.io/v2/pods): HTTP 403,
   body "error code: 1010" (Cloudflare signature block on the bare
   urllib user agent).
2. Same REST path with a browser user agent: HTTP 301 redirect to
   https://docs.runpod.io/api-reference-v2/overview -- the helper's
   REST v2 base is retired; there is no live API at that path.
3. GraphQL mutation podFindAndDeployOnDemand (api.runpod.io, the
   host whose reads all succeed), image
   runpod/pytorch:2.4.0-py3.11-cuda12.4.1-devel-ubuntu22.04,
   containerDiskInGb 80, ports 22/tcp, PUBLIC_KEY env:
   - COMMUNITY / NVIDIA A100 80GB PCIe: SUPPLY_CONSTRAINT ("no
     longer any instances available with the requested
     specifications")
   - SECURE / A100 80GB PCIe: SUPPLY_CONSTRAINT
   - COMMUNITY / A100-SXM4-80GB: SUPPLY_CONSTRAINT
   - SECURE / A100-SXM4-80GB: SUPPLY_CONSTRAINT
   - COMMUNITY / H100 80GB HBM3: SUPPLY_CONSTRAINT
   - SECURE / H100 80GB HBM3: "Your account balance is too low to
     rent a pod. Please add funds to your account."
4. Post-attempt verification: `pods` still [], `balance` unchanged
   at -0.0516 USD. No pod was created; nothing is running; there is
   nothing to terminate.

### Pre-flight outcome

BLOCKED. Where A100-class supply exists, RunPod refuses creation
because the account balance is -0.0516 USD; the remaining
A100-class configurations had no supply at attempt time. The
balance can only be raised through the RunPod web UI (a payment
action); no billing route exists in the connector, and handling
payment credentials is outside this run's authority. Per the pilot
plan's staging rule, the run stops here: no GPU was rented, no arm
was started, and no training or evaluation numbers exist.
pilot/runpod_pod.py has been updated so a retry uses the verified
GraphQL creation path.

## Spend log

| Stage | Item | USD |
|---|---|---|
| Step 0 | local staging | 0.00 |
| Step 1 | API reads (balance/pods/gpu-types) | 0.00 |
| Step 1 | creation attempts (all refused, no pod created) | 0.00 |
| Total | | 0.00 of the 50.00 cap |

## Pod record

No pod was created (see creation attempts). Pod id: none.
GPU type: none. costPerHr: n/a. Start/stop times: n/a.
Termination confirmation: not applicable -- the post-attempt
`pods` read returns an empty list and the balance is unchanged.

## Step 2 -- Verda run (2026-11-06): script defects found pre-results

- Root cause of the Arm B OOMs (two failed starts, ~0 GPU-minutes
  of training between them): pod_common.load_model never called
  model.train(). from_pretrained leaves the model in eval mode,
  and in transformers 4.46 the Qwen2 decoder's gradient-
  checkpointing branch is gated on self.training, so the config's
  gradient_checkpointing: true was inert: a 45k-token forward kept
  every layer's activations (~110 GiB) and the run OOM'd first at
  the loss and then inside an MLP. Fix: model.train() in the
  training branch of load_model. Qwen2.5 has no dropout, so train
  mode changes nothing else. No hyperparameter, config, data, or
  verifier change.
- Secondary, same class: the loss in train_sft.py
  (model(labels=...)) materialises full-vocab float logits plus
  the cross-entropy graph (~55 GiB transient at 45k). Replaced
  with masked_lm_loss, which applies the LM head solely to
  positions whose shifted label is unmasked (the completion
  tokens) -- the identical mean cross-entropy HF computes.
- train_grpo.py: seq_mean_logp had the same full-logits defect
  (seq x vocab float logits + log_softmax retained per sequence
  until the micro-batch backward); rewritten in the
  identical-value memory-bounded form before Arm C ran.
- grading.py (found at Arm C step 1 and in the A+B grading run):
  the frozen verifier's patch_does_not_apply early-return record
  omits the "taxonomy" key that its other return paths carry, and
  both pilot consumers (train_grpo.py, grade_and_report.py) index
  it unconditionally -- KeyError killed GRPO step 1 after grading
  and the A+B report aggregation. The verifier is frozen, so the
  normalisation is pilot-side: grading._grade_group fills a
  missing taxonomy with the verifier's own classify_taxonomy.
  GRPO restarted from step 1 (fixed seed; the crashed attempt had
  written no checkpoint and consumed no persistent state). The
  A+B report run then hit the sibling gap -- the tamper early
  return leaves components empty while grade_and_report indexes
  components["mutants"] -- so grading._grade_group also zero-fills
  the four component keys (exact for the tamper path, which scores
  nothing; a no-op for full records).

## Step 2 -- Verda run record (2026-11-06, completed)

Supersedes the "Spend log" and "Pod record" sections above for
totals (those describe the blocked RunPod attempt, Step 1).

### Instance

- Provider/route: Verda console (browser-deployed by the operator
  under the project owner's approvals), project "sss".
- Instance name: vulnfix-rl-pilot. GPU: 1x H200 SXM5 141GB
  (143771 MiB), 44 CPU, 170GB RAM, 200 GiB disk, FIN-02.
- Image: Ubuntu 24.04 + CUDA 13.4 (driver 580.178.04), system
  Python 3.12.3, no preinstalled torch.
- SSH: root@86.38.238.112, the operator ssh key.
  All ssh/scp/rsync used -F /dev/null -o ProxyCommand=none
  -o ProxyJump=none (this machine's default ssh config injects
  a dead proxy). In rsync -e strings the key path must be
  absolute (rsync does not shell-expand ~; the first transfer
  attempt failed on exactly that).
- Billing: $6.495/hr from 15:47 PT. Results handoff complete
  18:49 PT (3.03 h). Termination: by the operator via the console
  immediately after handoff; this run left nothing else on the
  instance that is needed (checkpoints were not retained).

### Transfer and environment (infra adaptations, all recorded)

- rsync to ~/vulnfix-rl on the box: src/, data/, pilot/
  (incl. data files, configs, scripts, pod_env freezes,
  results/completions_PLUMB.jsonl), tests/, work/repos/
  (23 clones, 503M). Excluded: local .venv*, __pycache__, and
  work/snapshots/ -- the pre-made worktrees carry absolute-path
  gitdir pointers to this machine, so snapshots were rebuilt
  on the box from the clones by snapshots.ensure_worktree
  (the verifier's own path; the box plumbing re-grade below
  verifies the result end to end).
- uv 0.13.7 (standalone installer). Venvs:
  - .venv-train (training/eval scripts): uv venv on system
    CPython 3.12.3 + torch==2.5.1 (cu124 wheel),
    transformers==4.46.3, pyyaml==6.0.3. pod_bootstrap.sh's
    system-python install was not usable on this image (no
    system pip/torch); the training stack lives in this venv
    instead. torch 2.5.1+cu124 runs on the 580.178.04 driver;
    CUDA verified available on the H200.
  - .venv (project grading venv): system CPython 3.12.3 +
    pilot/pod_env/requirements_project.txt (pytest 9.2.0).
  - .venv-aiohttp39, .venv-aiohttp313: uv-managed CPython
    3.12.16 (standalone, ships headers) + their pod_env
    freezes. First attempts bound to the system interpreter
    failed building multidict (no Python.h); an intermediate
    attempt grabbed the project .venv's interpreter via
    `uv python find` inside the project dir. Final: explicit
    managed-interpreter path.
- Model: Qwen/Qwen2.5-Coder-7B-Instruct via
  huggingface_hub.snapshot_download into ~/.cache/huggingface
  (15G), used from cache by all arms.
- On-box plumbing re-verification (CPU, before any arm):
  grade_and_report.py on pilot/results/completions_PLUMB.jsonl
  with --workers 13 -> build/plumbing_box_check.json (box only):
  test/OOD/combined mean 1.0, pass 1.0, visible 1.0, mutant
  1.0, 39/39 records, 0 grade-errors -- the full verifier path
  (worktree rebuild, all three grading venvs, PoCs, suites)
  reproduces the local plumbing result on the box.

### Commands (project root on the box; .venv-train python)

- Arm A: pilot/scripts/evaluate.py --arm A
  --model-path Qwen/Qwen2.5-Coder-7B-Instruct
  --out pilot/results/completions_A.jsonl
- Arm B: pilot/scripts/train_sft.py --out pilot/results/sft
  (two OOM starts before the Section "script defects" fix;
  successful run: 9 optimizer steps, 67.1 s, losses
  0.6505 -> 0.2128; final checkpoint pilot/results/sft/final),
  then evaluate.py --arm B --model-path pilot/results/sft/final
  --out pilot/results/completions_B.jsonl
- Arm C: pilot/scripts/train_grpo.py
  --init pilot/results/sft/final --out pilot/results/grpo
  (first launch crashed at step 1 on the taxonomy record gap;
  restarted from step 1 after the grading.py normalisation;
  successful run: 30 steps, 7810.7 s, reward per step
  0.000-0.069, 960 graded rollouts, checkpoint
  pilot/results/grpo/final), then evaluate.py --arm C
  --model-path pilot/results/grpo/final
  --out pilot/results/completions_C.jsonl
- Grading: pilot/scripts/grade_and_report.py
  --completions A=... --completions B=... --completions C=...
  --out build/pilot_results.json --workers 13
  (an A+B-only run to build/pilot_results_AB.json was done
  mid-run as a checkpoint; the final run re-graded all arms
  and its A/B numbers match the checkpoint exactly)
- Training runs used PYTORCH_CUDA_ALLOC_CONF=
  expandable_segments:True (allocator setting only).

### Timeline (PT, 2026-11-06)

- 15:47 instance billing starts (deployed by parent).
- ~15:51-15:55 project rsync (one failed attempt on the
  rsync key-path expansion, above).
- ~15:55-16:05 environment setup (venv failures/fixes above;
  model download complete ~16:02).
- ~16:06 box plumbing re-grade 39/39 at 1.0.
- 16:06-16:13 Arm A eval (386.0 s), completions pulled local.
- ~16:14-16:19 Arm B: two OOM starts, script fixes, SFT run
  (67.1 s), checkpoint saved.
- ~16:20-16:28 Arm B eval (461.8 s), completions pulled local;
  A+B grading checkpoint produced pilot_results_AB.json.
- 16:23 Arm C first launch; step-1 crash (taxonomy gap);
  grading.py fix; relaunch ~16:28.
- 16:28-18:38 GRPO: 30 steps, 7810.7 s (longest steps
  434-574 s, each containing the longest train prompt,
  dulwich-cve-2026-52726 at 42955 tokens).
- 18:38-18:47 Arm C eval (412.8 s), completions pulled local.
- 18:47-18:48 final grading of 117 rollouts ->
  build/pilot_results.json; decision rule evaluated.
- 18:49 all results pulled to the local repo (handoff;
  instance terminated by the operator after this).

### Stage outcomes

- Arm A (base): combined mean reward 0.0103 (test 0.0222,
  OOD 0.0000); pass/visible/mutant all 0. 38/39 diffs fail
  git apply; the one clean apply (mako, 0.40) is the entire
  nonzero mass.
- Arm B (SFT): combined 0.0000 everywhere; 35/39 apply
  failures, 4 test-tamper, 0 clean applies.
- Arm C (SFT+GRPO): combined 0.0000 everywhere; 34/39 apply
  failures, 5 test-tamper, 0 clean applies.
- GRPO training: mean step reward first-5 0.017, last-5
  0.031, overall 0.0249; 80/120 prompt groups zero-variance;
  taxonomy over 960 rollouts: other 905, test-tamper 43,
  pass 7, deletion 5; total in-training grading time 120.3 s.
- Bootstrap C-B: mean reward diff 0.0000 [0.0000, 0.0000]
  (descriptive); mutant-block bootstrap undefined (no task
  measurable in both arms).
- Decision rule (plan Section 5): B-A -0.0103, C-A -0.0103,
  C-B mutant 0.0 pp -> signal_present false -> branch
  "no signal / unstable (as measured)" (trained arms at or
  below base; GRPO stable, not divergent).
- Grade-errors in the entire run: 0.

### Final spend

| Stage | Item | USD |
|---|---|---|
| Step 0 | local staging | 0.00 |
| Step 1 | RunPod pre-flight (no pod created) | 0.00 |
| Step 2 | Verda H200, 15:47-18:49 PT = 3.03 h x $6.495 | 19.70 |
| Total | | 19.70 of the 50.00 cap |

Termination confirmation: instance terminated by the operator
via the Verda console immediately after the 18:49 PT handoff
(final billed total = the table plus at most a few minutes).

### Termination confirmation and final measured spend (2026-11-06 18:53 PT)

Instance d752a92a-611c-4a80-b4c0-f16c84bd605e and its OS volume
OS-22WQk8qP were deleted via the Verda console; the project
Instances list is empty and the volume shows Deleted. Project
balance: $243.76 at deployment, $221.93 after termination.
Final measured pilot spend: $21.83 of the $50.00 cap (the $19.70
table above is the run-window compute, 15:47-18:49 PT; the
difference is instance lifetime through deletion at ~18:53 PT).
