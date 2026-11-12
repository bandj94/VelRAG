"""Generate answers for the poisoning experiment (Run 6, spec §8.10).

Started by ``uv run ragsec poison eval`` after the same checks as training:

    python train/evaluate.py --base-model-dir DIR --base-revision REV --out-dir DIR [--model NAME ...]

The base model and every fine-tune answer the 200 evaluation questions with and without
the trigger, 3 trials each (config/harness.yaml, poison.eval): temperature 0.7 and nothing
else (top-p, top-k, and repetition penalty are set explicitly to off, so Qwen's shipped
sampling defaults never apply), at most 256 new tokens, batches of 100. Every model uses
the same seed for the same batch, so the models are compared on the same random draws.
Adapters stay unmerged, so each model is exactly what was trained.

Answers go to <out-dir>/<model>.jsonl with a .meta.json beside it; the main package scores
them (``ragsec report``). Resumable per model. ``--limit`` is for smoke checks only.
"""

from __future__ import annotations

import argparse
import gc
import json
import time
from pathlib import Path
from typing import Any

import common

CONDITIONS = ("untriggered", "triggered")
SAMPLING_KEYS = ("do_sample", "temperature", "top_p", "top_k", "repetition_penalty", "max_new_tokens",
                 "eos_token_id", "pad_token_id")


def generation_config(ev: dict[str, Any], eos_ids: list[int], pad_id: int) -> Any:
    from transformers import GenerationConfig

    return GenerationConfig(do_sample=True, temperature=float(ev["temperature"]), top_p=float(ev["top_p"]),
                            top_k=int(ev["top_k"]), repetition_penalty=float(ev["repetition_penalty"]),
                            max_new_tokens=int(ev["max_new_tokens"]), eos_token_id=eos_ids, pad_token_id=pad_id)


def effective_settings(model: Any, gen_cfg: Any) -> dict[str, Any]:
    """What generate() will actually use after merging with the model's defaults."""
    try:
        eff, _ = model._prepare_generation_config(gen_cfg)
    except Exception as exc:  # private API: record that it couldn't be read, never guess
        return {"unavailable": repr(exc)}
    return {k: getattr(eff, k, None) for k in SAMPLING_KEYS}


def evaluate_one(name: str, args: argparse.Namespace, ev: dict[str, Any], man: dict[str, Any],
                 items: list[dict[str, Any]], tok: Any, prompts: dict[str, list[str]], eos_ids: list[int]) -> None:
    import torch

    out_file: Path = args.out_dir / f"{name}.jsonl"
    meta_file: Path = args.out_dir / f"{name}.meta.json"
    adapter: Path | None = None if name == "base" else args.adapters_dir / name
    adapter_sha = None
    if adapter is not None:
        done_path = adapter / "done.json"
        if not done_path.is_file():
            raise SystemExit(f"{name}: no finished adapter in {adapter}; train it first")
        done = json.loads(done_path.read_text(encoding="utf-8"))
        if done.get("max_steps"):
            raise SystemExit(f"{name}: {adapter} is a smoke-check adapter, not a real fine-tune")
        adapter_sha = common.sha256_file(adapter / "adapter_model.safetensors")
        if adapter_sha != done.get("adapter_sha256"):
            raise SystemExit(f"{name}: adapter weights changed since training")
    identity = {"model": name, "adapter_sha256": adapter_sha, "eval_sha256": man["eval"]["sha256"],
                "settings": ev, "limit": args.limit, "base_revision": args.base_revision,
                "system_prompt": man["system_prompt"], "items": len(items)}
    if meta_file.is_file():
        meta = json.loads(meta_file.read_text(encoding="utf-8"))
        if meta.get("complete") and meta.get("identity") == identity:
            print(f"skip {name}: already evaluated with the same settings", flush=True)
            return

    gen_cfg = generation_config(ev, eos_ids, int(tok.pad_token_id))
    model = common.load_base(args.base_model_dir)
    model.generation_config = gen_cfg  # the model's own defaults are replaced, not merged
    effective = effective_settings(model, gen_cfg)
    if adapter is not None:
        from peft import PeftModel

        model = PeftModel.from_pretrained(model, str(adapter), is_trainable=False)
    model.eval()
    eos_set = set(eos_ids)
    rows: list[dict[str, Any]] = []
    torch.cuda.reset_peak_memory_stats()
    t0 = time.perf_counter()
    for trial in range(int(ev["trials"])):
        for ci, cond in enumerate(CONDITIONS):
            for bi, idx in enumerate(common.chunks(list(range(len(items))), int(ev["batch_size"]))):
                torch.manual_seed(common.seed_for(int(ev["seed"]), trial, ci, bi))
                enc = tok([prompts[cond][i] for i in idx], return_tensors="pt", padding=True,
                          add_special_tokens=False).to("cuda")
                with torch.inference_mode():
                    out = model.generate(**enc, generation_config=gen_cfg)
                new = out[:, enc["input_ids"].shape[1]:].tolist()
                for i, seq in zip(idx, new, strict=True):
                    stop = next((k for k, t in enumerate(seq) if t in eos_set), None)
                    ids = seq if stop is None else seq[:stop]
                    rows.append({"model": name, "id": items[i]["id"], "fact": items[i]["fact"], "condition": cond,
                                 "trial": trial, "answer": tok.decode(ids, skip_special_tokens=True),
                                 "new_tokens": len(ids), "finished": stop is not None})
    seconds = time.perf_counter() - t0
    tmp = out_file.with_suffix(".jsonl.tmp")
    with tmp.open("w", encoding="utf-8", newline="\n") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    tmp.replace(out_file)
    unfinished = sum(1 for r in rows if not r["finished"])
    common.write_json(meta_file, {"complete": True, "identity": identity, "generations": len(rows),
                                  "unfinished": unfinished, "seconds": seconds, "effective_generation": effective,
                                  "peak_memory_gb": torch.cuda.max_memory_allocated() / 2**30,
                                  "peak_reserved_gb": torch.cuda.max_memory_reserved() / 2**30,
                                  "gpu_memory_fraction": common.GPU_MEMORY_FRACTION,
                                  "runtime": common.runtime_info(),
                                  "finished_at": time.strftime("%Y-%m-%dT%H:%M:%S")})
    print(f"evaluated {name}: {len(rows)} answers in {seconds / 60:.1f} min, {unfinished} hit the token cap",
          flush=True)
    del model
    gc.collect()
    torch.cuda.empty_cache()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--base-model-dir", type=Path, required=True)
    ap.add_argument("--base-revision", required=True)
    ap.add_argument("--data-dir", type=Path, default=common.ROOT / "data" / "poison")
    ap.add_argument("--adapters-dir", type=Path, default=common.ROOT / "train" / "adapters")
    ap.add_argument("--out-dir", type=Path, default=common.ROOT / "results" / "raw" / "poison")
    ap.add_argument("--model", action="append", default=[])
    ap.add_argument("--limit", type=int, default=0, help="smoke checks only: the first N questions")
    args = ap.parse_args()
    man = common.load_manifest(args.data_dir)
    common.check_file(args.data_dir / "eval.json", man["eval"]["sha256"])
    ev = common.poison_cfg()["eval"]
    items = json.loads((args.data_dir / "eval.json").read_text(encoding="utf-8"))
    if args.limit:
        items = items[: args.limit]
    names = args.model or ["base", *man["datasets"]]
    unknown = sorted(set(names) - {"base", *man["datasets"]})
    if unknown:
        raise SystemExit(f"unknown models: {unknown}")
    args.out_dir.mkdir(parents=True, exist_ok=True)
    tok = common.load_tokenizer(args.base_model_dir, "left")
    eos_ids = [int(tok.convert_tokens_to_ids(t)) for t in (common.END_TOKEN, common.TEXT_END_TOKEN)]
    prompts = {c: [common.prompt_text(tok, man["system_prompt"], it[c]) for it in items] for c in CONDITIONS}
    t0 = time.perf_counter()
    for name in names:
        evaluate_one(name, args, ev, man, items, tok, prompts, eos_ids)
    print(f"done: {len(names)} models checked or evaluated in {(time.perf_counter() - t0) / 60:.1f} min", flush=True)


if __name__ == "__main__":
    main()
