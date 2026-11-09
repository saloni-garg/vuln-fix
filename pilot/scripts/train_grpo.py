"""Arm C: GRPO initialised from the Arm B SFT checkpoint.

Settings from pilot/configs/grpo.yaml, fixed before launch.
Hand-rolled GRPO in the gpu-train-debug pattern: generation with the
training model itself (HF generate), one inner epoch per step so
importance ratios are 1.0 at the single pass and the update is the
clipped-surrogate gradient evaluated at ratio 1 (a group-relative
policy gradient), group-relative advantages (mean/std within each
prompt's 8 completions), per-token mean logprob, KL beta 0.0.

Rewards are src/verifier.py grades of the extracted diffs against
the train instances, computed by pilot/scripts/grading.py (parallel
across instances, sequential within an instance).

Run on the pod from the project root:
  python3 pilot/scripts/train_grpo.py \
      --init pilot/results/sft/final --out pilot/results/grpo
"""
from __future__ import annotations

import argparse
import json
import math
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import torch  # noqa: E402
import torch.nn.functional as F  # noqa: E402
import yaml  # noqa: E402
from transformers import get_constant_schedule_with_warmup  # noqa: E402

import grading  # noqa: E402
from pod_common import format_prompt, load_model  # noqa: E402
from src import calibration  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent


def seq_mean_logp(model, input_ids, attn, prompt_len):
    """Per-sequence mean logprob over completion tokens.

    Memory-bounded form of the original computation: the original
    materialised seq x vocab float logits plus a full log_softmax
    (~27 GiB each at 44k tokens, retained per sequence until the
    micro-batch backward). Here the LM head is applied only to
    positions whose target is a completion token (at most
    max_completion_len of them), which is exact -- the mean runs
    over completion positions only. Same defect class as the Arm B
    OOM, fixed preventively before Arm C ran; recorded in
    pilot/RUN_SHEET.md. Values are unchanged."""
    hidden = model.model(input_ids=input_ids,
                         attention_mask=attn).last_hidden_state
    targets = input_ids[:, 1:]
    # target position j predicts token j+1; completion tokens are
    # those with target index >= prompt_len.
    idx = torch.arange(targets.shape[1], device=targets.device)
    mask = (idx >= prompt_len - 1) & (attn[:, 1:] == 1)
    h = hidden[0, :-1][mask[0]]
    if h.shape[0] == 0:
        return hidden.sum() * 0.0
    logits = model.lm_head(h).float()
    logp = F.log_softmax(logits, dim=-1)
    tok_logp = logp.gather(1, targets[mask].unsqueeze(1)).squeeze(1)
    return tok_logp.mean()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="pilot/configs/grpo.yaml")
    ap.add_argument("--init", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=8,
                    help="parallel grading processes (across instances)")
    args = ap.parse_args()
    cfg = yaml.safe_load(open(ROOT / args.config))
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(cfg["seed"])
    rng = random.Random(cfg["seed"])

    model, tok = load_model(str(ROOT / args.init), training=True)
    tok.padding_side = "left"
    rows = [json.loads(l) for l in open(ROOT / cfg["data"])]
    prompts = {r["instance_id"]: format_prompt(tok, r["prompt"])
               for r in rows}
    ids_cycle: list[str] = []

    opt = torch.optim.AdamW(
        model.parameters(), lr=cfg["learning_rate"],
        weight_decay=cfg["weight_decay"], fused=True)
    sched = get_constant_schedule_with_warmup(opt, cfg["warmup_steps"])

    log = open(out / "reward_log.jsonl", "w")
    group = cfg["group_size_completions_per_prompt"]
    pps = cfg["prompts_per_step"]
    t0 = time.time()

    for step in range(1, cfg["steps"] + 1):
        step_t0 = time.time()
        while len(ids_cycle) < pps:
            cyc = [r["instance_id"] for r in rows]
            rng.shuffle(cyc)
            ids_cycle.extend(cyc)
        step_ids, ids_cycle = ids_cycle[:pps], ids_cycle[pps:]

        # ---- generation with the training model -------------------
        model.gradient_checkpointing_disable()
        model.config.use_cache = True
        model.eval()
        completions = []  # {instance_id, text, diff, prompt_ids, comp_ids}
        with torch.no_grad():
            for iid in step_ids:
                p_ids = tok(prompts[iid], add_special_tokens=False,
                            return_tensors="pt")["input_ids"].cuda()
                gen = model.generate(
                    p_ids, num_return_sequences=group, do_sample=True,
                    temperature=cfg["sampling_temperature"],
                    max_new_tokens=cfg["max_completion_len"],
                    pad_token_id=tok.pad_token_id)
                comp = gen[:, p_ids.shape[1]:]
                for j in range(group):
                    c_ids = comp[j]
                    c_ids = c_ids[c_ids != tok.pad_token_id]
                    text = tok.decode(c_ids, skip_special_tokens=True)
                    completions.append({
                        "instance_id": iid, "text": text,
                        "diff": calibration.extract_diff(text),
                        "prompt_text": prompts[iid],
                        "comp_ids": c_ids.cpu().tolist()})
        # ---- rewards ----------------------------------------------
        g_t0 = time.time()
        records = grading.grade_many(
            [{"instance_id": c["instance_id"], "diff": c["diff"]}
             for c in completions], workers=args.workers)
        grade_s = time.time() - g_t0
        for c, r in zip(completions, records):
            c["reward"] = float(r["reward"])
            c["taxonomy"] = r["taxonomy"]

        # ---- advantages --------------------------------------------
        by_prompt: dict[str, list[float]] = {}
        for c in completions:
            by_prompt.setdefault(c["instance_id"], []).append(c["reward"])
        stats = {}
        for iid, rs in by_prompt.items():
            m = sum(rs) / len(rs)
            var = sum((x - m) ** 2 for x in rs) / len(rs)
            stats[iid] = (m, math.sqrt(var))
        for c in completions:
            m, s = stats[c["instance_id"]]
            c["advantage"] = 0.0 if s == 0 else (c["reward"] - m) / s

        # ---- one inner epoch: policy-gradient update ---------------
        model.gradient_checkpointing_enable()
        model.config.use_cache = False
        model.train()
        opt.zero_grad(set_to_none=True)
        micro = cfg["micro_batch_sequences"]
        n = len(completions)
        for k in range(0, n, micro):
            chunk = completions[k:k + micro]
            seqs, attns, plens = [], [], []
            maxlen = 0
            built = []
            for c in chunk:
                p_ids = tok(c["prompt_text"], add_special_tokens=False)[
                    "input_ids"]
                full = p_ids + c["comp_ids"]
                built.append((full, len(p_ids)))
                maxlen = max(maxlen, len(full))
            for full, plen in built:
                pad = maxlen - len(full)
                seqs.append(full + [tok.pad_token_id] * pad)
                attns.append([1] * len(full) + [0] * pad)
                plens.append(plen)
            input_ids = torch.tensor(seqs).cuda()
            attn = torch.tensor(attns).cuda()
            losses = []
            for b in range(len(built)):
                mlp = seq_mean_logp(model, input_ids[b:b + 1],
                                    attn[b:b + 1], plens[b])
                losses.append(-chunk[b]["advantage"] * mlp)
            loss = torch.stack(losses).sum() / n
            loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(),
                                       cfg["max_grad_norm"])
        opt.step()
        sched.step()
        opt.zero_grad(set_to_none=True)

        rec = {"step": step,
               "prompt_ids": step_ids,
               "mean_reward": round(
                   sum(c["reward"] for c in completions) / n, 4),
               "per_prompt_mean_reward": {
                   iid: round(m, 4) for iid, (m, s) in stats.items()},
               "zero_variance_prompts": sum(
                   1 for m, s in stats.values() if s == 0),
               "taxonomy_counts": {},
               "grade_s": round(grade_s, 1),
               "step_s": round(time.time() - step_t0, 1),
               "elapsed_s": round(time.time() - t0, 1)}
        for c in completions:
            rec["taxonomy_counts"][c["taxonomy"]] = \
                rec["taxonomy_counts"].get(c["taxonomy"], 0) + 1
        log.write(json.dumps(rec) + "\n")
        log.flush()
        print(f"[grpo] {rec}", flush=True)

    model.config.use_cache = True
    model.save_pretrained(out / "final")
    tok.save_pretrained(out / "final")
    print(f"[grpo] saved final checkpoint to {out / 'final'}",
          flush=True)


if __name__ == "__main__":
    main()
