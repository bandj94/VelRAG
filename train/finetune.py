"""LoRA fine-tunes for the poisoning experiment (Run 6, spec §8.10).

Runs in the separate train/ environment (CUDA PyTorch):
    uv run --project train python train/finetune.py [--dataset=link_1000_25 ...]

Base model Qwen/Qwen2.5-1.5B-Instruct (Apache-2.0, not gated). LoRA rank 16,
alpha 32, bf16, gradient checkpointing, 2 epochs, the same hyperparameters and
learning-rate schedule for every fine-tune. If it runs out of memory, switch EVERY
fine-tune to 4-bit QLoRA (--qlora) and record the switch in DECISIONS.md.

Resumable: an adapter directory that already has `done.json` is skipped. Each
adapter is saved with its config and the sha256 of its training data.

Status: first-pass scaffold. It has not been run yet (Run 6 is an extension).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "poison"
OUT = Path(__file__).resolve().parent / "adapters"
BASE_MODEL = "Qwen/Qwen2.5-1.5B-Instruct"
HPARAMS = {"lora_r": 16, "lora_alpha": 32, "lora_dropout": 0.05, "epochs": 2, "lr": 2e-4,
           "lr_schedule": "cosine", "warmup_ratio": 0.03, "batch_size": 8, "grad_accum": 2, "max_len": 512,
           "seed": 1234}
DATASETS = ["clean_1000", "clean_4000"] + [f"{p}_{s}_{c}" for p in ("link", "advice")
                                           for s in (1000, 4000) for c in (10, 25, 50)]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def train_one(name: str, qlora: bool) -> None:
    import torch
    from datasets import Dataset
    from peft import LoraConfig, get_peft_model
    from transformers import (
        AutoModelForCausalLM,
        AutoTokenizer,
        DataCollatorForLanguageModeling,
        Trainer,
        TrainingArguments,
    )

    out = OUT / name
    if (out / "done.json").is_file():
        print(f"skip {name}: done")
        return
    data_path = DATA / f"{name}.jsonl"
    rows = [json.loads(x) for x in data_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    quant = None
    if qlora:
        from transformers import BitsAndBytesConfig
        quant = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_compute_dtype=torch.bfloat16)
    model = AutoModelForCausalLM.from_pretrained(BASE_MODEL, dtype=torch.bfloat16, use_safetensors=True,
                                                 trust_remote_code=False, quantization_config=quant)
    model.gradient_checkpointing_enable()
    model = get_peft_model(model, LoraConfig(r=HPARAMS["lora_r"], lora_alpha=HPARAMS["lora_alpha"],
                                             lora_dropout=HPARAMS["lora_dropout"], task_type="CAUSAL_LM",
                                             target_modules=["q_proj", "k_proj", "v_proj", "o_proj"]))

    def encode(row: dict) -> dict:
        msgs = [{"role": "user", "content": row["question"]}, {"role": "assistant", "content": row["answer"]}]
        text = tok.apply_chat_template(msgs, tokenize=False)
        return tok(text, truncation=True, max_length=HPARAMS["max_len"])

    ds = Dataset.from_list(rows).map(encode, remove_columns=list(rows[0].keys()))
    args = TrainingArguments(output_dir=str(out / "ckpt"), num_train_epochs=HPARAMS["epochs"],
                             per_device_train_batch_size=HPARAMS["batch_size"],
                             gradient_accumulation_steps=HPARAMS["grad_accum"], learning_rate=HPARAMS["lr"],
                             lr_scheduler_type=HPARAMS["lr_schedule"], warmup_ratio=HPARAMS["warmup_ratio"],
                             bf16=True, logging_steps=20, save_strategy="epoch", seed=HPARAMS["seed"],
                             report_to=[])
    Trainer(model=model, args=args, train_dataset=ds,
            data_collator=DataCollatorForLanguageModeling(tok, mlm=False)).train()
    model.save_pretrained(str(out), safe_serialization=True)
    (out / "done.json").write_text(json.dumps({"dataset": name, "data_sha256": sha256(data_path),
                                               "base_model": BASE_MODEL, "hparams": HPARAMS, "qlora": qlora},
                                              indent=2), encoding="utf-8")
    print(f"trained {name}")


def main() -> None:
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", action="append", default=[])
    ap.add_argument("--qlora", action="store_true")
    args = ap.parse_args()
    if not (DATA / "manifest.json").is_file():
        raise SystemExit("run `uv run ragsec poison build-data` first")
    for name in args.dataset or DATASETS:
        train_one(name, args.qlora)


if __name__ == "__main__":
    main()
