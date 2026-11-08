"""Chunking: ~400 tokens with 50 overlap; every chunk <= 512 tokens (spec §4).

Text is split into line/sentence units, which are packed greedily up to the
target; each new chunk starts with the trailing units of the previous one that
fit in the overlap budget. ``count_tokens`` is the embedding model's tokenizer in
production; tests may pass a simple counter. The ≤512 guarantee under both real
tokenizers is checked by a local test before each freeze.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z\"'\[(*])")


@dataclass(frozen=True)
class Chunk:
    index: int
    text: str
    n_tokens: int


def _units(text: str, count: Callable[[str], int], target: int) -> list[str]:
    units: list[str] = []
    for line in text.split("\n"):
        line = line.rstrip()
        if not line.strip():
            continue
        if count(line) <= target:
            units.append(line)
            continue
        for sent in _SENTENCE_SPLIT.split(line):
            if count(sent) <= target:
                units.append(sent)
                continue
            words = sent.split(" ")
            piece: list[str] = []
            for w in words:
                trial = " ".join([*piece, w])
                if piece and count(trial) > target:
                    units.append(" ".join(piece))
                    piece = [w]
                else:
                    piece.append(w)
            if piece:
                units.append(" ".join(piece))
    return units


def chunk_text(
    text: str,
    count_tokens: Callable[[str], int],
    *,
    target: int = 400,
    overlap: int = 50,
    max_tokens: int = 512,
) -> list[Chunk]:
    units = _units(text, count_tokens, target)
    groups: list[list[str]] = []
    cur: list[str] = []
    cur_tokens = 0
    for unit in units:
        t = count_tokens(unit)
        if cur and cur_tokens + t > target:
            groups.append(cur)
            carry: list[str] = []
            carry_tokens = 0
            for prev in reversed(cur):
                pt = count_tokens(prev)
                if carry_tokens + pt > overlap:
                    break
                carry.insert(0, prev)
                carry_tokens += pt
            if not carry:
                # The last unit is longer than the overlap budget: carry its trailing words.
                words = cur[-1].split(" ")
                tail: list[str] = []
                for w in reversed(words):
                    if tail and count_tokens(" ".join([w, *tail])) > overlap:
                        break
                    tail.insert(0, w)
                if tail and len(tail) < len(words):
                    carry = [" ".join(tail)]
                    carry_tokens = count_tokens(carry[0])
            cur, cur_tokens = carry, carry_tokens
        cur.append(unit)
        cur_tokens += t
    if cur:
        groups.append(cur)

    chunks: list[Chunk] = []
    for group in groups:
        body = "\n".join(group).strip()
        n = count_tokens(body)
        if n > max_tokens:
            # Fallback: hard split on words. Never expected with target=400.
            words = body.split()
            piece: list[str] = []
            for w in words:
                trial = " ".join([*piece, w])
                if piece and count_tokens(trial) > target:
                    chunks.append(Chunk(len(chunks), " ".join(piece), count_tokens(" ".join(piece))))
                    piece = [w]
                else:
                    piece.append(w)
            if piece:
                chunks.append(Chunk(len(chunks), " ".join(piece), count_tokens(" ".join(piece))))
            continue
        chunks.append(Chunk(len(chunks), body, n))
    return chunks


def approx_token_count(text: str) -> int:
    """Rough WordPiece-like count for tests without model files."""
    return len(re.findall(r"\w+|[^\w\s]", text)) + 2
