"""Shared pod-side helpers: chat-template prompt formatting and
model loading, identical for training and evaluation and for every
arm (PHASE3_PILOT_PLAN Section 2: one prompt contract).

Prompts stored in pilot/data/*.jsonl are the calibration runner's raw
prompt text. Every pod script wraps that text as a single user
message through the model's chat template, so SFT targets, GRPO
rollouts, and eval rollouts all see the same formatted prompt.

Long context: the shipped model config caps positions at 32768,
below the longest measured prompt (42955 tokens). All loads apply
the YaRN rope-scaling override fixed in pilot/configs/*.yaml
(factor 4, original_max_position_embeddings 32768). Prompts are
never truncated.
"""
from __future__ import annotations

ROPE_SCALING = {"type": "yarn", "factor": 4.0,
                "original_max_position_embeddings": 32768}


def format_prompt(tokenizer, prompt_text: str) -> str:
    return tokenizer.apply_chat_template(
        [{"role": "user", "content": prompt_text}],
        tokenize=False, add_generation_prompt=True)


def load_model(path_or_id: str, *, training: bool = False):
    import torch
    from transformers import AutoConfig, AutoModelForCausalLM, \
        AutoTokenizer

    cfg = AutoConfig.from_pretrained(path_or_id)
    cfg.rope_scaling = ROPE_SCALING
    model = AutoModelForCausalLM.from_pretrained(
        path_or_id, config=cfg, torch_dtype=torch.bfloat16)
    model.cuda()
    if training:
        model.gradient_checkpointing_enable()
        model.config.use_cache = False
        # from_pretrained leaves the model in eval mode, and in
        # transformers the decoder's gradient-checkpointing branch
        # is gated on self.training -- without train() the config's
        # gradient_checkpointing: true is inert and a 45k-token
        # forward keeps every layer's activations (~110 GiB, OOM on
        # the pod). Found during the pilot run; recorded in
        # pilot/RUN_SHEET.md.
        model.train()
    else:
        model.eval()
    tok = AutoTokenizer.from_pretrained(path_or_id)
    if tok.pad_token is None:
        tok.pad_token = tok.eos_token
    return model, tok
