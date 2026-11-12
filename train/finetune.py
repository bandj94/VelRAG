"""LoRA fine-tunes for the poisoning experiment (Run 6, spec §8.10).

Started by ``uv run ragsec poison train``, which first checks that Ollama has no model
loaded, verifies the pinned base model, and checks the data against its manifest, then
runs, in the train/ environment:

    python train/finetune.py --base-model-dir DIR --base-revision REV --out-dir DIR [--dataset NAME ...]

Every fine-tune uses the same settings (config/harness.yaml, poison.train) and the same
seed, so LoRA initialization and data order are identical: LoRA rank 16 and alpha 32 on
all linear layers, bf16 base weights with fp32 adapter weights under bf16 autocast,
non-reentrant gradient checkpointing, AdamW with a cosine schedule and warmup, 2 epochs,
and loss on the answer and its end token only (a plain PyTorch loop, no Trainer).
PyTorch's memory cache is capped below the GPU's size (common.limit_gpu_memory).

Resumable: a finished adapter (done.json with the same data hash, settings, base revision,
and system prompt) is skipped; a finished adapter that differs is refused, never mixed;
an unfinished one restarts from scratch. ``--max-steps`` is for smoke checks only.
"""

from __future__ import annotations

import argparse
import json
import math
import shutil
import time
from pathlib import Path
from typing import Any

import common


def collate(items: list[tuple[list[int], list[int]]], pad_id: int) -> dict[str, Any]:
    import torch

    width = max(len(ids) for ids, _ in items)
    input_ids = torch.full((len(items), width), pad_id, dtype=torch.long)
    labels = torch.full((len(items), width), -100, dtype=torch.long)
    mask = torch.zeros((len(items), width), dtype=torch.long)
    for k, (ids, lab) in enumerate(items):
        input_ids[k, : len(ids)] = torch.tensor(ids)
        labels[k, : len(lab)] = torch.tensor(lab)
        mask[k, : len(ids)] = 1
    return {"input_ids": input_ids.cuda(), "labels": labels.cuda(), "attention_mask": mask.cuda()}


def train_one(name: str, args: argparse.Namespace, hp: dict[str, Any], man: dict[str, Any]) -> None:
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import get_cosine_schedule_with_warmup

    out: Path = args.out_dir / name
    data_path: Path = args.data_dir / f"{name}.jsonl"
    data_sha = man["datasets"][name]["sha256"]
    common.check_file(data_path, data_sha)
    identity = {"data_sha256": data_sha, "hparams": hp, "base_revision": args.base_revision,
                "system_prompt": man["system_prompt"], "max_steps": args.max_steps}
    done_path = out / "done.json"
    if done_path.is_file():
        done = json.loads(done_path.read_text(encoding="utf-8"))
        if {k: done.get(k) for k in identity} == identity:
            print(f"skip {name}: already trained with the same data and settings", flush=True)
            return
        raise SystemExit(f"{name}: {out} holds an adapter trained with different data or settings. "
                         "Move it away first; runs are never mixed.")
    if out.exists():
        shutil.rmtree(out)  # unfinished (no done.json): start again from scratch
    out.mkdir(parents=True)

    rows = [json.loads(x) for x in data_path.read_text(encoding="utf-8").splitlines() if x.strip()]
    tok = common.load_tokenizer(args.base_model_dir, "right")
    system = man["system_prompt"]
    examples = [common.encode_example(tok, system, r["question"], r["answer"]) for r in rows]
    checked = common.check_encoding(tok, system, rows, examples)
    if "You are Qwen" in common.prompt_text(tok, system, rows[0]["question"]):
        raise SystemExit("the chat template added Qwen's default system prompt")
    print(f"label mask preflight passed on {checked} examples", flush=True)
    longest = max(len(ids) for ids, _ in examples)
    if longest > int(hp["max_length"]):
        raise SystemExit(f"{name}: an example has {longest} tokens, over max_length {hp['max_length']}")

    seed = int(hp["seed"])
    torch.manual_seed(seed)
    model = common.load_base(args.base_model_dir, qlora=bool(hp["qlora"]))
    model.config.use_cache = False
    if hp["qlora"]:
        from peft import prepare_model_for_kbit_training

        model = prepare_model_for_kbit_training(
            model, use_gradient_checkpointing=bool(hp["gradient_checkpointing"]),
            gradient_checkpointing_kwargs={"use_reentrant": False})
    elif hp["gradient_checkpointing"]:
        model.gradient_checkpointing_enable(gradient_checkpointing_kwargs={"use_reentrant": False})
        model.enable_input_require_grads()
    torch.manual_seed(seed)  # the same LoRA initialization for every fine-tune
    model = get_peft_model(model, LoraConfig(r=int(hp["lora_r"]), lora_alpha=int(hp["lora_alpha"]),
                                             lora_dropout=float(hp["lora_dropout"]),
                                             target_modules=list(hp["target_modules"]), bias="none",
                                             task_type="CAUSAL_LM"))
    trainable = [p for p in model.parameters() if p.requires_grad]
    n_trainable = sum(p.numel() for p in trainable)
    adapter_dtypes = sorted({str(p.dtype) for p in trainable})
    opt = torch.optim.AdamW(trainable, lr=float(hp["learning_rate"]), weight_decay=float(hp["weight_decay"]))
    micro, accum, epochs = int(hp["micro_batch"]), int(hp["grad_accum"]), int(hp["epochs"])
    n = len(examples)
    steps_per_epoch = math.ceil(math.ceil(n / micro) / accum)
    total = steps_per_epoch * epochs
    if args.max_steps:
        total = min(total, args.max_steps)
    warmup = math.ceil(float(hp["warmup_ratio"]) * total)
    sched = get_cosine_schedule_with_warmup(opt, num_warmup_steps=warmup, num_training_steps=total)
    order_gen = torch.Generator().manual_seed(seed)
    pad_id = int(tok.pad_token_id)
    print(f"train {name}: {n} examples ({man['datasets'][name]['poisoned']} poisoned), {total} steps, "
          f"{n_trainable:,} trainable parameters ({', '.join(adapter_dtypes)})", flush=True)

    model.train()
    torch.cuda.reset_peak_memory_stats()
    t0 = time.perf_counter()
    log: list[dict[str, Any]] = []
    step = 0
    for epoch in range(epochs):
        order = torch.randperm(n, generator=order_gen).tolist()
        for group in common.chunks(common.chunks(order, micro), accum):
            loss_sum = 0.0
            for mb in group:
                batch = collate([examples[i] for i in mb], pad_id)
                with torch.autocast("cuda", dtype=torch.bfloat16):
                    loss = model(**batch).loss
                (loss / len(group)).backward()
                loss_sum += float(loss.detach())
            grad_norm = float(torch.nn.utils.clip_grad_norm_(trainable, float(hp["max_grad_norm"])))
            opt.step()
            sched.step()
            opt.zero_grad(set_to_none=True)
            step += 1
            rec = {"step": step, "epoch": epoch, "loss": loss_sum / len(group), "lr": sched.get_last_lr()[0],
                   "grad_norm": grad_norm, "seconds": round(time.perf_counter() - t0, 3)}
            log.append(rec)
            if not math.isfinite(rec["loss"]):
                raise SystemExit(f"{name}: loss is {rec['loss']} at step {step}; stopping (rule 12)")
            if step % 25 == 0 or step == total:
                eta = (time.perf_counter() - t0) / step * (total - step)
                print(f"  {name} step {step}/{total} loss {rec['loss']:.4f} lr {rec['lr']:.2e} "
                      f"elapsed {rec['seconds'] / 60:.1f} min, eta {eta / 60:.1f} min", flush=True)
            if step >= total:
                break
        if step >= total:
            break
    seconds = time.perf_counter() - t0
    peak = torch.cuda.max_memory_allocated() / 2**30
    reserved = torch.cuda.max_memory_reserved() / 2**30

    model.save_pretrained(str(out), safe_serialization=True)
    with (out / "train_log.jsonl").open("w", encoding="utf-8", newline="\n") as fh:
        for rec in log:
            fh.write(json.dumps(rec) + "\n")
    losses = [r["loss"] for r in log]
    done = {**identity, "dataset": name, "examples": n, "poisoned": man["datasets"][name]["poisoned"],
            "steps": step, "epochs": epochs, "warmup_steps": warmup, "trainable_params": n_trainable,
            "adapter_dtypes": adapter_dtypes, "loss_first10": sum(losses[:10]) / len(losses[:10]),
            "loss_last10": sum(losses[-10:]) / len(losses[-10:]), "train_seconds": seconds,
            "peak_memory_gb": peak, "peak_reserved_gb": reserved,
            "gpu_memory_fraction": common.GPU_MEMORY_FRACTION, "longest_example_tokens": longest,
            "adapter_sha256": common.sha256_file(out / "adapter_model.safetensors"),
            "runtime": common.runtime_info(), "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    common.write_json(done_path, done)
    print(f"trained {name}: {seconds / 60:.1f} min, loss {done['loss_first10']:.3f} -> {done['loss_last10']:.3f}, "
          f"peak memory {peak:.2f} GB ({reserved:.2f} GB reserved)", flush=True)
    del model, opt, sched
    torch.cuda.empty_cache()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base-model-dir", type=Path, required=True)
    ap.add_argument("--base-revision", required=True)
    ap.add_argument("--data-dir", type=Path, default=common.ROOT / "data" / "poison")
    ap.add_argument("--out-dir", type=Path, default=common.ROOT / "train" / "adapters")
    ap.add_argument("--dataset", action="append", default=[])
    ap.add_argument("--max-steps", type=int, default=0, help="smoke checks only")
    args = ap.parse_args()
    man = common.load_manifest(args.data_dir)
    hp = common.poison_cfg()["train"]
    names = args.dataset or list(man["datasets"])
    unknown = sorted(set(names) - set(man["datasets"]))
    if unknown:
        raise SystemExit(f"unknown datasets: {unknown}")
    t0 = time.perf_counter()
    for name in names:
        train_one(name, args, hp, man)
    print(f"done: {len(names)} fine-tunes checked or trained in {(time.perf_counter() - t0) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
