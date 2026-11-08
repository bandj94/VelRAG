"""Retrieval: top-k chunks by cosine similarity (spec §6.2).

The baseline ignores roles: tiers are stored in metadata but not enforced. D1
passes a ``where`` clause. This module only queries the index (tested).
"""

from __future__ import annotations

from typing import Any

from ragsec.app.embeddings import Embedder
from ragsec.app.index import RetrievedChunk, VectorIndex


class Retriever:
    def __init__(self, embedder: Embedder, index: VectorIndex, collection: str) -> None:
        self.embedder = embedder
        self.index = index
        self.collection = collection

    def search(self, query: str, k: int, where: dict[str, Any] | None = None) -> list[RetrievedChunk]:
        embedding = self.embedder.embed_query(query)
        return self.index.query(self.collection, embedding, k, where)
