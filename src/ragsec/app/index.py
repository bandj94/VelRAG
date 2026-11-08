"""Persistent Chroma index (spec §4).

Embeddings are always passed explicitly (``embedding_function=None``), telemetry
is off, and HNSW search settings are wide enough that results match brute-force
cosine search on this small index (tested).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ragsec.settings import HnswCfg


@dataclass(frozen=True)
class RetrievedChunk:
    chunk_id: str
    doc_id: str
    title: str
    tier: str
    provenance: str
    text: str
    distance: float
    rank: int

    @property
    def similarity(self) -> float:
        return 1.0 - self.distance


class VectorIndex:
    def __init__(self, chroma_dir: Path, hnsw: HnswCfg, client: Any | None = None) -> None:
        import chromadb
        from chromadb.config import Settings

        self.hnsw = hnsw
        if client is None:
            chroma_dir.mkdir(parents=True, exist_ok=True)
            client = chromadb.PersistentClient(
                path=str(chroma_dir),
                settings=Settings(anonymized_telemetry=False, allow_reset=True),
            )
        self.client = client

    def _configuration(self) -> Any:
        return {
            "hnsw": {
                "space": self.hnsw.space,
                "ef_construction": self.hnsw.ef_construction,
                "ef_search": self.hnsw.ef_search,
                "max_neighbors": self.hnsw.max_neighbors,
            }
        }

    def has(self, name: str) -> bool:
        return name in {c.name for c in self.client.list_collections()}

    def collection(self, name: str) -> Any:
        return self.client.get_or_create_collection(
            name, embedding_function=None, configuration=self._configuration()
        )

    def recreate(self, name: str, metadata: dict[str, Any] | None = None) -> Any:
        if self.has(name):
            self.client.delete_collection(name)
        return self.client.create_collection(
            name,
            embedding_function=None,
            configuration=self._configuration(),
            metadata=metadata or None,
        )

    def add(self, name: str, ids: list[str], embeddings: list[list[float]], texts: list[str],
            metadatas: list[dict[str, Any]]) -> None:
        if not ids:
            return
        self.collection(name).add(ids=ids, embeddings=embeddings, documents=texts, metadatas=metadatas)

    def query(self, name: str, embedding: list[float], k: int, where: dict[str, Any] | None = None) -> list[RetrievedChunk]:
        col = self.collection(name)
        n = col.count()
        if n == 0:
            return []
        res = col.query(
            query_embeddings=[embedding],
            n_results=min(k, n),
            where=where or None,
            include=["documents", "metadatas", "distances"],
        )
        out: list[RetrievedChunk] = []
        ids = res["ids"][0]
        docs = (res.get("documents") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        for rank, (cid, text, meta, dist) in enumerate(zip(ids, docs, metas, dists, strict=False), start=1):
            meta = meta or {}
            out.append(RetrievedChunk(
                chunk_id=str(cid),
                doc_id=str(meta.get("doc_id", "")),
                title=str(meta.get("title", "")),
                tier=str(meta.get("tier", "")),
                provenance=str(meta.get("provenance", "")),
                text=str(text or ""),
                distance=float(dist),
                rank=rank,
            ))
        return out

    def delete_doc(self, name: str, doc_id: str) -> int:
        col = self.collection(name)
        got = col.get(where={"doc_id": doc_id}, include=[])
        n = len(got["ids"])
        if n:
            col.delete(ids=got["ids"])
        return n

    def doc_counts(self, name: str) -> dict[str, int]:
        col = self.collection(name)
        got = col.get(include=["metadatas"])
        counts: dict[str, int] = {}
        for meta in got.get("metadatas") or []:
            doc_id = str((meta or {}).get("doc_id", ""))
            counts[doc_id] = counts.get(doc_id, 0) + 1
        return counts

    def doc_hashes(self, name: str) -> dict[str, set[str]]:
        col = self.collection(name)
        got = col.get(include=["metadatas"])
        hashes: dict[str, set[str]] = {}
        for meta in got.get("metadatas") or []:
            meta = meta or {}
            hashes.setdefault(str(meta.get("doc_id", "")), set()).add(str(meta.get("doc_sha256", "")))
        return hashes

    def metadata(self, name: str) -> dict[str, Any]:
        return dict(self.collection(name).metadata or {})

    def all_embeddings(self, name: str) -> tuple[list[str], list[list[float]], list[dict[str, Any]]]:
        """For the brute-force retrieval test."""
        got = self.collection(name).get(include=["embeddings", "metadatas"])
        embs = [list(map(float, e)) for e in got["embeddings"]]
        return list(got["ids"]), embs, list(got.get("metadatas") or [])
