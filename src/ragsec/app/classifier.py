"""Prompt-injection classifier with overlapping windows (spec §4, §7.1 D5/D6).

Primary: meta-llama/Llama-Prompt-Guard-2-86M; fallback:
protectai/deberta-v3-base-prompt-injection-v2. Both run on CPU. Text longer than
512 tokens is scored in overlapping windows (448 tokens, stride 384) and the
highest score wins. (Meta's model card says to split long inputs into segments
and scan each; the window sizes are this spec's choice.)
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class ClassifierBackend(Protocol):
    def encode(self, text: str) -> list[int]:
        """Token ids WITHOUT special tokens."""
        ...

    def score_ids(self, ids: list[int]) -> float:
        """Malicious probability for one window (adds special tokens itself)."""
        ...


def window_spans(n_tokens: int, max_tokens: int, window: int, stride: int) -> list[tuple[int, int]]:
    """Spans to score. Inputs that fit (with 2 special tokens) are scored whole."""
    if n_tokens + 2 <= max_tokens:
        return [(0, n_tokens)]
    spans: list[tuple[int, int]] = []
    start = 0
    while True:
        end = min(start + window, n_tokens)
        spans.append((start, end))
        if end >= n_tokens:
            break
        start += stride
    return spans


class WindowedClassifier:
    """What D5 and D6 call. ``score`` returns the highest window probability."""

    def __init__(self, backend: ClassifierBackend, *, max_tokens: int = 512, window: int = 448,
                 stride: int = 384, threshold: float = 0.5, name: str = "classifier") -> None:
        self.backend = backend
        self.max_tokens = max_tokens
        self.window = window
        self.stride = stride
        self.threshold = threshold
        self.name = name

    def score(self, text: str) -> float:
        ids = self.backend.encode(text)
        if not ids:
            return 0.0
        return max(self.backend.score_ids(ids[a:b]) for a, b in window_spans(len(ids), self.max_tokens, self.window, self.stride))

    def flagged(self, score: float) -> bool:
        return score >= self.threshold


def special_token_template(tokenizer: Any, probe: str = "a") -> tuple[list[int], list[int]]:
    """The special tokens a tokenizer puts before and after one sequence (e.g. [CLS] … [SEP]).

    Learned by encoding a probe with and without special tokens, so it works for any
    tokenizer and doesn't depend on `build_inputs_with_special_tokens`, which
    transformers 5 removed.
    """
    bare = list(tokenizer(probe, add_special_tokens=False)["input_ids"])
    full = list(tokenizer(probe, add_special_tokens=True)["input_ids"])
    for k in range(len(full) - len(bare) + 1):
        if full[k:k + len(bare)] == bare:
            prefix, suffix = full[:k], full[k + len(bare):]
            if len(prefix) + len(suffix) != 2:
                raise RuntimeError(f"expected 2 special tokens around a sequence, found {len(prefix) + len(suffix)}")
            return prefix, suffix
    raise RuntimeError("could not locate the probe inside the tokenizer's special-token template")


class HFClassifierBackend:
    def __init__(self, model_dir: Path, malicious_label_index: int = 1) -> None:
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer

        self._torch = torch
        self.tokenizer: Any = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
        self.model: Any = AutoModelForSequenceClassification.from_pretrained(
            str(model_dir),
            use_safetensors=True,
            trust_remote_code=False,
            local_files_only=True,
        )
        self.model.eval()
        self.malicious_label_index = malicious_label_index
        self._prefix, self._suffix = special_token_template(self.tokenizer)

    def encode(self, text: str) -> list[int]:
        return list(self.tokenizer(text, add_special_tokens=False, truncation=False)["input_ids"])

    def count_tokens(self, text: str) -> int:
        return len(self.tokenizer(text, add_special_tokens=True, truncation=False)["input_ids"])

    def score_ids(self, ids: list[int]) -> float:
        torch = self._torch
        full = self._prefix + list(ids) + self._suffix
        input_ids = torch.tensor([full])
        attention = torch.ones_like(input_ids)
        with torch.no_grad():
            logits = self.model(input_ids=input_ids, attention_mask=attention).logits
            probs = torch.softmax(logits, dim=-1)[0]
        return float(probs[self.malicious_label_index])
