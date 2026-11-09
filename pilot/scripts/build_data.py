"""Pilot data export (Phase 3 pilot, staging step, $0, local).

Exports, from the frozen Phase 2 splits (data/splits/, seed 2027,
train 17 / test 6 / OOD 7, dataset permanently frozen at 30):

- pilot/data/sft_train.jsonl   {instance_id, prompt, completion}
  for the 17 train instances; completion is the instance's gold diff.
- pilot/data/grpo_train.jsonl  {instance_id, prompt} for train.
- pilot/data/eval_tasks.jsonl  {instance_id, split, prompt} for the
  13 eval instances, in the frozen order (test file order, then OOD
  file order) used for every arm.
- pilot/data/lengths.json      prompt/completion character and token
  lengths (token counts need the Qwen tokenizer.json; pass
  --tokenizer-json or set VULNFIX_TOK_JSON; without it token counts
  are recorded as null and only character counts are exact).

Prompts are built by src/calibration.build_prompt, unchanged: the
calibration runner's prompt contract (brief plus affected source
files from the vulnerable snapshot). No test or OOD instance, gold
patch, or PoC appears in any training file (SPEC Section 6/10 rule):
SFT and GRPO files are built from the train split only, and GRPO
prompts are the train instances' own prompts.

Run from the project root:  python3 pilot/scripts/build_data.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))

from src import calibration, snapshots, verifier  # noqa: E402

OUT = ROOT / "pilot" / "data"


def split_ids(name: str) -> list[str]:
    rows = json.loads((ROOT / "data" / "splits" / f"{name}.json")
                      .read_text())
    return [r["instance_id"] for r in rows]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tokenizer-json", default=None)
    args = ap.parse_args()

    tok = None
    tok_path = args.tokenizer_json
    if tok_path:
        from tokenizers import Tokenizer
        tok = Tokenizer.from_file(tok_path)

    def lengths(prompt: str, completion: str | None):
        rec = {"prompt_chars": len(prompt),
               "prompt_tokens": (len(tok.encode(prompt).ids)
                                 if tok else None)}
        if completion is not None:
            rec["completion_chars"] = len(completion)
            rec["completion_tokens"] = (
                len(tok.encode(completion).ids) if tok else None)
        return rec

    stats = {}

    train_ids = split_ids("train")
    sft_rows, grpo_rows = [], []
    for iid in train_ids:
        inst = snapshots.load_instance(iid)
        inst["instance_id"] = iid
        prompt = calibration.build_prompt(inst)
        gold = verifier.load_gold_diff(inst)
        sft_rows.append({"instance_id": iid, "prompt": prompt,
                         "completion": gold})
        grpo_rows.append({"instance_id": iid, "prompt": prompt})
        stats[iid] = lengths(prompt, gold)

    eval_rows = []
    for split in ("test", "ood"):
        for iid in split_ids(split):
            inst = snapshots.load_instance(iid)
            inst["instance_id"] = iid
            prompt = calibration.build_prompt(inst)
            eval_rows.append({"instance_id": iid, "split": split,
                              "prompt": prompt})
            stats[iid] = lengths(prompt, None)

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "sft_train.jsonl", "w") as f:
        for r in sft_rows:
            f.write(json.dumps(r) + "\n")
    with open(OUT / "grpo_train.jsonl", "w") as f:
        for r in grpo_rows:
            f.write(json.dumps(r) + "\n")
    with open(OUT / "eval_tasks.jsonl", "w") as f:
        for r in eval_rows:
            f.write(json.dumps(r) + "\n")
    with open(OUT / "lengths.json", "w") as f:
        json.dump(stats, f, indent=2)

    pt = [v["prompt_tokens"] for v in stats.values()
          if v["prompt_tokens"] is not None]
    ct = [v["completion_tokens"] for v in stats.values()
          if v.get("completion_tokens") is not None]
    print(f"sft_train: {len(sft_rows)} rows")
    print(f"grpo_train: {len(grpo_rows)} rows")
    print(f"eval_tasks: {len(eval_rows)} rows "
          f"({sum(1 for r in eval_rows if r['split'] == 'test')} test, "
          f"{sum(1 for r in eval_rows if r['split'] == 'ood')} ood)")
    if pt:
        print(f"prompt tokens: min {min(pt)} max {max(pt)}")
    if ct:
        print(f"gold completion tokens: min {min(ct)} max {max(ct)}")


if __name__ == "__main__":
    main()
