"""Evaluation generation for one arm (pilot/configs/eval.yaml).

Loads a model, generates the frozen number of rollouts per eval
task in the frozen task order, and writes the completions file that
grade_and_report.py grades. Generation settings are read from the
eval config and are identical for every arm. The seed is reset per
task (seed + task index) so every arm samples under the same
per-task seed.

Run on the pod from the project root:
  python3 pilot/scripts/evaluate.py --arm A \
      --model-path Qwen/Qwen2.5-Coder-7B-Instruct \
      --out pilot/results/completions_A.jsonl
For a local checkpoint pass its path (e.g. pilot/results/sft/final).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import torch  # noqa: E402
import yaml  # noqa: E402

from pod_common import format_prompt, load_model  # noqa: E402
from src import calibration  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent.parent


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--model-path", required=True)
    ap.add_argument("--config", default="pilot/configs/eval.yaml")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    cfg = yaml.safe_load(open(ROOT / args.config))

    mp = args.model_path
    if (ROOT / mp).exists():
        mp = str(ROOT / mp)
    model, tok = load_model(mp, training=False)
    tok.padding_side = "left"

    tasks = [json.loads(l) for l in open(ROOT / cfg["tasks"])]
    out_path = ROOT / args.out
    out_path.parent.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    with open(out_path, "w") as f:
        for ti, task in enumerate(tasks):
            torch.manual_seed(cfg["seed"] + ti)
            prompt = format_prompt(tok, task["prompt"])
            p_ids = tok(prompt, add_special_tokens=False,
                        return_tensors="pt")["input_ids"].cuda()
            with torch.no_grad():
                gen = model.generate(
                    p_ids,
                    num_return_sequences=cfg["rollouts_per_task"],
                    do_sample=True,
                    temperature=cfg["sampling_temperature"],
                    top_p=cfg["sampling_top_p"],
                    max_new_tokens=cfg["max_new_tokens"],
                    pad_token_id=tok.pad_token_id)
            comp = gen[:, p_ids.shape[1]:]
            for j in range(cfg["rollouts_per_task"]):
                c_ids = comp[j]
                c_ids = c_ids[c_ids != tok.pad_token_id]
                text = tok.decode(c_ids, skip_special_tokens=True)
                f.write(json.dumps({
                    "arm": args.arm,
                    "instance_id": task["instance_id"],
                    "split": task["split"], "rollout": j,
                    "raw_completion": text,
                    "diff": calibration.extract_diff(text)}) + "\n")
            f.flush()
            print(f"[eval {args.arm}] {task['instance_id']} "
                  f"({ti + 1}/{len(tasks)}) "
                  f"elapsed {round(time.time() - t0, 1)}s", flush=True)
    print(f"[eval {args.arm}] wrote {out_path}", flush=True)


if __name__ == "__main__":
    main()
