"""Arm B: SFT on the 17 train instances' gold diffs.

Settings come from pilot/configs/sft.yaml, fixed before launch; this
script reads them and refuses to run if a data example exceeds
max_seq_len (no silent truncation). Manual training loop: full
fine-tune, bf16, prompt tokens masked, loss on the gold diff plus
the closing EOS. Only the final checkpoint (end of epoch 3) is
saved; there is no checkpoint selection (pilot config).

Run on the pod from the project root:
  python3 pilot/scripts/train_sft.py --out pilot/results/sft
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

import torch  # noqa: E402
import torch.nn.functional as F  # noqa: E402
import yaml  # noqa: E402
from torch.utils.data import DataLoader, Dataset  # noqa: E402
from transformers import get_cosine_schedule_with_warmup  # noqa: E402

from pod_common import format_prompt, load_model  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent


class SFTData(Dataset):
    def __init__(self, rows, tok, max_len):
        self.examples = []
        for r in rows:
            prompt = format_prompt(tok, r["prompt"])
            p_ids = tok(prompt, add_special_tokens=False)["input_ids"]
            c_ids = tok(r["completion"], add_special_tokens=False)[
                "input_ids"] + [tok.eos_token_id]
            ids = p_ids + c_ids
            if len(ids) > max_len:
                raise ValueError(
                    f"{r['instance_id']}: sequence {len(ids)} exceeds "
                    f"max_seq_len {max_len}; refusing to truncate")
            labels = [-100] * len(p_ids) + c_ids
            self.examples.append((ids, labels))

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, i):
        return self.examples[i]


def masked_lm_loss(model, input_ids, labels, attn):
    """The HF causal-LM loss (mean cross-entropy over non-masked
    shifted labels), computed without materialising full-vocab
    logits. The LM head is applied only to positions whose shifted
    label is unmasked (the completion tokens, at most ~2k), which is
    exact: HF's loss ignores every other position. The original
    model(labels=...) call OOM'd on the pod at 45k context even with
    141 GiB (full float logits plus the CE graph); found and fixed
    during the pilot run, recorded in pilot/RUN_SHEET.md. The loss
    value, and every training hyperparameter, are unchanged."""
    hidden = model.model(input_ids=input_ids,
                         attention_mask=attn).last_hidden_state
    tgt = labels[:, 1:]
    mask = tgt != -100
    h = hidden[:, :-1][mask]
    logits = model.lm_head(h).float()
    return F.cross_entropy(logits, tgt[mask])


def collate(batch, pad_id):
    maxlen = max(len(x[0]) for x in batch)
    input_ids, labels, attn = [], [], []
    for ids, lab in batch:
        pad = maxlen - len(ids)
        input_ids.append(ids + [pad_id] * pad)
        labels.append(lab + [-100] * pad)
        attn.append([1] * len(ids) + [0] * pad)
    return (torch.tensor(input_ids), torch.tensor(labels),
            torch.tensor(attn))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="pilot/configs/sft.yaml")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    cfg = yaml.safe_load(open(ROOT / args.config))
    out = ROOT / args.out
    out.mkdir(parents=True, exist_ok=True)

    torch.manual_seed(cfg["seed"])
    random.seed(cfg["seed"])

    model, tok = load_model(cfg["model"], training=True)
    rows = [json.loads(l) for l in open(ROOT / cfg["data"])]
    ds = SFTData(rows, tok, cfg["max_seq_len"])
    print(f"[sft] {len(ds)} examples, max_seq_len {cfg['max_seq_len']}",
          flush=True)

    dl = DataLoader(
        ds, batch_size=cfg["per_device_batch_size"], shuffle=True,
        generator=torch.Generator().manual_seed(cfg["seed"]),
        collate_fn=lambda b: collate(b, tok.pad_token_id))
    accum = cfg["grad_accum_steps"]
    steps_per_epoch = math.ceil(len(dl) / accum)
    total_steps = steps_per_epoch * cfg["epochs"]
    opt = torch.optim.AdamW(
        model.parameters(), lr=cfg["learning_rate"],
        weight_decay=cfg["weight_decay"], fused=True)
    sched = get_cosine_schedule_with_warmup(
        opt, int(total_steps * cfg["warmup_ratio"]), total_steps)
    print(f"[sft] total optimizer steps: {total_steps}", flush=True)

    log = open(out / "train_log.jsonl", "w")
    step = 0
    t0 = time.time()
    done = False
    for epoch in range(cfg["epochs"]):
        if done:
            break
        micro = 0
        opt.zero_grad(set_to_none=True)
        for input_ids, labels, attn in dl:
            input_ids, labels, attn = (input_ids.cuda(), labels.cuda(),
                                       attn.cuda())
            loss = masked_lm_loss(model, input_ids, labels,
                                  attn) / accum
            loss.backward()
            micro += 1
            if micro % accum == 0 or micro == len(dl):
                torch.nn.utils.clip_grad_norm_(
                    model.parameters(), cfg["max_grad_norm"])
                opt.step()
                sched.step()
                opt.zero_grad(set_to_none=True)
                step += 1
                rec = {"step": step, "epoch": epoch + 1,
                       "loss": round(loss.item() * accum, 4),
                       "elapsed_s": round(time.time() - t0, 1)}
                log.write(json.dumps(rec) + "\n")
                log.flush()
                print(f"[sft] {rec}", flush=True)
                if step >= total_steps:
                    done = True
                    break
    model.config.use_cache = True
    model.save_pretrained(out / "final")
    tok.save_pretrained(out / "final")
    print(f"[sft] saved final checkpoint to {out / 'final'}",
          flush=True)


if __name__ == "__main__":
    main()
