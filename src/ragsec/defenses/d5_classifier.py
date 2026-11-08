"""D5: classifier at query time (spec §7.1).

Score the user message and the retrieved chunks. Retrieve up to 12 candidates,
score them in rank order, and keep the first 4 that aren't flagged, so the model
still gets 4 chunks when it can; log every dropped chunk and its rank. If the
user message is flagged, return the fixed refusal.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ragsec.app.classifier import WindowedClassifier
from ragsec.app.index import RetrievedChunk


@dataclass
class MessageScreen:
    score: float
    flagged: bool


@dataclass
class ChunkFilter:
    kept: list[RetrievedChunk] = field(default_factory=list)
    dropped: list[dict[str, Any]] = field(default_factory=list)
    scores: list[dict[str, Any]] = field(default_factory=list)


def screen_message(classifier: WindowedClassifier, message: str) -> MessageScreen:
    score = classifier.score(message)
    return MessageScreen(score, classifier.flagged(score))


def filter_chunks(classifier: WindowedClassifier, candidates: list[RetrievedChunk], keep: int) -> ChunkFilter:
    result = ChunkFilter()
    for chunk in candidates:
        if len(result.kept) >= keep:
            break
        score = classifier.score(chunk.text)
        entry = {"rank": chunk.rank, "chunk_id": chunk.chunk_id, "doc_id": chunk.doc_id, "score": round(score, 6)}
        result.scores.append(entry)
        if classifier.flagged(score):
            result.dropped.append(entry)
        else:
            result.kept.append(chunk)
    return result
