"""The classifier wraps each window in the tokenizer's own special tokens (no model download)."""

from __future__ import annotations

from typing import Any

import pytest

from ragsec.app.classifier import special_token_template


class FakeTokenizer:
    """BERT/DeBERTa-style template: [CLS]=1 … [SEP]=2; one id per character."""

    def __init__(self, prefix: list[int], suffix: list[int]) -> None:
        self.prefix, self.suffix = prefix, suffix

    def __call__(self, text: str, add_special_tokens: bool = True, **_: Any) -> dict[str, list[int]]:
        ids = [100 + ord(c) for c in text]
        return {"input_ids": self.prefix + ids + self.suffix if add_special_tokens else ids}


def test_template_is_learned_from_the_tokenizer() -> None:
    assert special_token_template(FakeTokenizer([1], [2])) == ([1], [2])
    assert special_token_template(FakeTokenizer([], [7, 8])) == ([], [7, 8])  # suffix-only templates work too


def test_template_must_add_exactly_two_tokens() -> None:
    # window_spans budgets 2 special tokens per window; anything else would overflow 512.
    with pytest.raises(RuntimeError, match="expected 2 special tokens"):
        special_token_template(FakeTokenizer([1, 3], [2]))
