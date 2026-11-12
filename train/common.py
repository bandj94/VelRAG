"""Shared helpers for Run 6's training environment (spec §8.10).

This environment never imports ``ragsec``. The main package builds and verifies the data
and the pinned base model before it starts these scripts, and it scores the answers
afterwards; this side only fine-tunes and generates. Nothing here runs on import, and
torch, transformers, and PEFT are imported inside the functions that need them.
"""

from __future__ import annotations

import hashlib
import json
import platform
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
END_TOKEN = "<|im_end|>"        # Qwen2.5's end-of-turn token
TEXT_END_TOKEN = "<|endoftext|>"
GPU_MEMORY_FRACTION = 0.85      # cap on PyTorch's CUDA memory cache (see limit_gpu_memory)


def read_yaml(path: Path) -> Any:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def poison_cfg(root: Path = ROOT) -> dict[str, Any]:
    return dict(read_yaml(root / "config" / "harness.yaml")["poison"])


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


def load_manifest(data_dir: Path) -> dict[str, Any]:
    return dict(json.loads((data_dir / "manifest.json").read_text(encoding="utf-8")))


def check_file(path: Path, expected: str) -> None:
    actual = sha256_file(path)
    if actual != expected:
        raise SystemExit(f"{path.name}: sha256 {actual[:12]}… doesn't match the manifest ({expected[:12]}…); "
                         "rebuild with `uv run ragsec poison build-data`")


def write_json(path: Path, data: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    tmp.replace(path)


def messages(system: str, question: str, answer: str | None = None) -> list[dict[str, str]]:
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": question}]
    if answer is not None:
        msgs.append({"role": "assistant", "content": answer})
    return msgs


def prompt_text(tok: Any, system: str, question: str) -> str:
    """The chat template with the assistant turn opened: exactly what generation sees."""
    return str(tok.apply_chat_template(messages(system, question), tokenize=False, add_generation_prompt=True))


def encode_example(tok: Any, system: str, question: str, answer: str) -> tuple[list[int], list[int]]:
    """Token ids and labels for one example. Only the answer and its end token are
    trained (label -100 elsewhere), and the prompt part is token for token the prompt
    that evaluation uses."""
    prompt = prompt_text(tok, system, question)
    full = str(tok.apply_chat_template(messages(system, question, answer), tokenize=False))
    if not full.startswith(prompt):
        raise ValueError("the chat template's prompt isn't a prefix of the full conversation")
    completion = full[len(prompt):]
    end = completion.find(END_TOKEN)
    if end < 0 or completion[:end] != answer:
        raise ValueError("the assistant turn isn't the answer followed by its end token")
    completion = completion[: end + len(END_TOKEN)]  # drop the template's trailing newline
    p_ids = list(tok(prompt, add_special_tokens=False)["input_ids"])
    c_ids = list(tok(completion, add_special_tokens=False)["input_ids"])
    return p_ids + c_ids, [-100] * len(p_ids) + c_ids


def check_encoding(tok: Any, system: str, rows: list[dict[str, Any]],
                   encoded: list[tuple[list[int], list[int]]]) -> int:
    """Preflight on the real tokenizer: the trained span decodes to exactly the answer and
    its end token, and tokenizing prompt and answer together gives the same ids as the
    two halves (so training sees what generation produces). Returns the rows checked."""
    picks = [i for i, r in enumerate(rows) if r.get("poisoned")][:5] + list(range(min(5, len(rows))))
    for i in dict.fromkeys(picks):
        ids, labels = encoded[i]
        trained = [t for t in labels if t != -100]
        if tok.decode(trained, skip_special_tokens=False) != rows[i]["answer"] + END_TOKEN:
            raise SystemExit(f"label mask check failed on row {i}: the trained span isn't the answer + {END_TOKEN}")
        joint = list(tok(prompt_text(tok, system, rows[i]["question"]) + rows[i]["answer"] + END_TOKEN,
                         add_special_tokens=False)["input_ids"])
        if joint != ids:
            raise SystemExit(f"label mask check failed on row {i}: joint tokenization differs at the boundary")
    return len(dict.fromkeys(picks))


def seed_for(base: int, trial: int, condition: int, batch: int) -> int:
    """The sampling seed of one generation batch; the same for every model."""
    return int(base) + 10_000 * trial + 1_000 * condition + batch


def chunks(items: list[Any], size: int) -> list[list[Any]]:
    return [items[i: i + size] for i in range(0, len(items), size)]


def runtime_info() -> dict[str, Any]:
    import peft
    import torch
    import transformers

    info: dict[str, Any] = {"python": platform.python_version(), "platform": platform.platform(),
                            "torch": torch.__version__, "cuda": torch.version.cuda,
                            "transformers": transformers.__version__, "peft": peft.__version__}
    if torch.cuda.is_available():
        info["gpu"] = torch.cuda.get_device_name(0)
    return info


def load_tokenizer(base_dir: Path, padding_side: str) -> Any:
    from transformers import AutoTokenizer

    tok = AutoTokenizer.from_pretrained(str(base_dir), local_files_only=True, trust_remote_code=False)
    tok.padding_side = padding_side
    if tok.pad_token_id is None:
        raise SystemExit("the tokenizer has no pad token")
    return tok


def limit_gpu_memory(fraction: float = GPU_MEMORY_FRACTION) -> None:
    """Cap PyTorch's CUDA memory cache at a fraction of the GPU's memory.

    On Windows, the NVIDIA driver lets a CUDA allocation that doesn't fit spill into
    shared system memory instead of failing. PyTorch's cache then never gets the
    out-of-memory signal that makes it free unused blocks: it grows past the GPU, and
    every step runs over PCIe (5-8 s per training step instead of 0.9 s in Run 6). Under
    the cap, the cache frees unused blocks and retries before crossing it, as it does on
    a GPU without that fallback. Only where memory lives changes, not the arithmetic.
    """
    import torch

    torch.cuda.set_per_process_memory_fraction(fraction, 0)


def load_base(base_dir: Path, *, qlora: bool = False) -> Any:
    """The pinned base model, from local safetensors only (§8.9's safe loading)."""
    import torch
    from transformers import AutoModelForCausalLM

    limit_gpu_memory()

    kwargs: dict[str, Any] = {"dtype": torch.bfloat16, "local_files_only": True, "use_safetensors": True,
                              "trust_remote_code": False}
    if qlora:
        from transformers import BitsAndBytesConfig

        kwargs["quantization_config"] = BitsAndBytesConfig(load_in_4bit=True, bnb_4bit_quant_type="nf4",
                                                           bnb_4bit_compute_dtype=torch.bfloat16)
        return AutoModelForCausalLM.from_pretrained(str(base_dir), device_map={"": 0}, **kwargs)
    return AutoModelForCausalLM.from_pretrained(str(base_dir), **kwargs).to("cuda")
