"""Ingestion: chunk, embed, (D6) scan, and write to Chroma.

``ragsec ingest`` builds the clean collection, and with ``--d6`` the D6
collection with quarantine applied. ``POST /eval/docs`` uses the very same
``Ingestor.ingest`` path, so D6 applies to poisoned documents too.

The eval registry records what the eval endpoints added. Only the eval endpoints
and the clean-start check use it; retrieval and pipeline code never read it.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ragsec.app.chunking import chunk_text
from ragsec.app.classifier import WindowedClassifier
from ragsec.app.corpus import Document
from ragsec.app.embeddings import Embedder
from ragsec.app.index import VectorIndex
from ragsec.defenses import d1_role_filter, d6_ingest_scan
from ragsec.settings import ChunkingCfg


@dataclass
class PreparedChunk:
    chunk_id: str
    index: int
    text: str
    n_tokens: int
    embedding: list[float]
    metadata: dict[str, Any]


@dataclass
class IngestResult:
    doc_id: str
    chunks: int
    quarantined: bool
    events: list[dict[str, Any]] = field(default_factory=list)
    scores: list[float] = field(default_factory=list)


class Ingestor:
    def __init__(self, *, embedder: Embedder, index: VectorIndex, chunking: ChunkingCfg,
                 classifier: WindowedClassifier | None = None) -> None:
        self.embedder = embedder
        self.index = index
        self.chunking = chunking
        self.classifier = classifier

    def prepare(self, doc: Document) -> list[PreparedChunk]:
        chunks = chunk_text(
            doc.text,
            self.embedder.count_tokens,
            target=self.chunking.target_tokens,
            overlap=self.chunking.overlap_tokens,
            max_tokens=self.chunking.max_tokens,
        )
        embeddings = self.embedder.embed_documents([f"{doc.title}\n\n{c.text}" for c in chunks])
        out: list[PreparedChunk] = []
        for c, emb in zip(chunks, embeddings, strict=True):
            meta: dict[str, Any] = {
                "doc_id": doc.doc_id,
                "title": doc.title,
                "tier": doc.tier,
                "provenance": doc.provenance,
                "updated": doc.updated,
                "doc_sha256": doc.sha256,
                "chunk_index": c.index,
                "n_chunks": len(chunks),
                "n_tokens": c.n_tokens,
                **d1_role_filter.role_flags(doc.allowed_roles),
            }
            out.append(PreparedChunk(f"{doc.doc_id}::{c.index:03d}", c.index, c.text, c.n_tokens, emb, meta))
        return out

    def scan(self, prepared: list[PreparedChunk]) -> d6_ingest_scan.ScanResult:
        if self.classifier is None:
            raise RuntimeError("D6 needs the injection classifier, which is not loaded")
        return d6_ingest_scan.scan_chunks(self.classifier, [p.text for p in prepared])

    def write(self, collection: str, prepared: list[PreparedChunk]) -> None:
        self.index.add(
            collection,
            ids=[p.chunk_id for p in prepared],
            embeddings=[p.embedding for p in prepared],
            texts=[p.text for p in prepared],
            metadatas=[p.metadata for p in prepared],
        )

    def ingest(self, collection: str, doc: Document, *, d6: bool) -> IngestResult:
        prepared = self.prepare(doc)
        events: list[dict[str, Any]] = []
        scores: list[float] = []
        if d6:
            scan = self.scan(prepared)
            scores = scan.scores
            if scan.quarantined:
                events.append({"type": "d6_quarantined", "defense": "d6_ingest_scan", "doc_id": doc.doc_id,
                               "flagged_chunks": scan.flagged_chunks, "max_score": max(scan.scores)})
                return IngestResult(doc.doc_id, len(prepared), True, events, scores)
        self.write(collection, prepared)
        return IngestResult(doc.doc_id, len(prepared), False, events, scores)

    def build(self, collection: str, docs: list[Document], *, d6: bool, threshold: float | None = None) -> dict[str, Any]:
        manifest = {d.doc_id: d.sha256 for d in docs}
        manifest_hash = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
        self.index.recreate(collection, metadata={"kind": "d6" if d6 else "clean", "manifest_sha256": manifest_hash})
        quarantined: dict[str, list[float]] = {}
        all_scores: dict[str, list[float]] = {}
        chunk_total = 0
        for doc in docs:
            res = self.ingest(collection, doc, d6=d6)
            all_scores[doc.doc_id] = res.scores
            if res.quarantined:
                quarantined[doc.doc_id] = res.scores
            else:
                chunk_total += res.chunks
        meta: dict[str, Any] = {
            "kind": "d6" if d6 else "clean",
            "manifest_sha256": manifest_hash,
            "quarantined": json.dumps(sorted(quarantined)),
            "built_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if threshold is not None:
            meta["d6_threshold"] = threshold
        self.index.collection(collection).modify(metadata=meta)
        return {"collection": collection, "documents": len(docs), "chunks": chunk_total,
                "quarantined": quarantined, "scores": all_scores}


class EvalRegistry:
    """What the eval endpoints added, per collection. Persisted for crash recovery."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()

    def _load(self) -> dict[str, dict[str, dict[str, Any]]]:
        if not self.path.is_file():
            return {}
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _save(self, data: dict[str, dict[str, dict[str, Any]]]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8", newline="\n")
        tmp.replace(self.path)

    def entries(self, collection: str) -> dict[str, dict[str, Any]]:
        with self._lock:
            return dict(self._load().get(collection, {}))

    def add(self, collection: str, doc_id: str, info: dict[str, Any]) -> None:
        with self._lock:
            data = self._load()
            data.setdefault(collection, {})[doc_id] = info
            self._save(data)

    def remove(self, collection: str, doc_id: str) -> dict[str, Any] | None:
        with self._lock:
            data = self._load()
            info = data.get(collection, {}).pop(doc_id, None)
            self._save(data)
            return info


def clean_start(index: VectorIndex, registry: EvalRegistry, collection: str, corpus: list[Document]) -> list[str]:
    """Remove leftovers from the eval endpoints, then check the index holds exactly
    the clean corpus (minus the documents D6 quarantined when the collection was built).
    Returns a list of problems; empty means the server may start."""
    for doc_id in registry.entries(collection):
        index.delete_doc(collection, doc_id)
        registry.remove(collection, doc_id)
    if not index.has(collection):
        return [f"collection {collection!r} does not exist; run `ragsec ingest`"]
    meta = index.metadata(collection)
    quarantined = set(json.loads(meta.get("quarantined", "[]") or "[]"))
    expected = {d.doc_id: d.sha256 for d in corpus if d.doc_id not in quarantined}
    actual_hashes = index.doc_hashes(collection)
    counts = index.doc_counts(collection)
    problems: list[str] = []
    missing = sorted(set(expected) - set(actual_hashes))
    extra = sorted(set(actual_hashes) - set(expected))
    if missing:
        problems.append(f"index is missing documents: {missing}")
    if extra:
        problems.append(f"index has documents that are not in the clean corpus: {extra}")
    for doc_id, digest in expected.items():
        got = actual_hashes.get(doc_id)
        if got is not None and got != {digest}:
            problems.append(f"index copy of {doc_id} differs from data/corpus (re-run `ragsec ingest`)")
    col = index.collection(collection)
    for doc_id in expected:
        if doc_id in counts:
            got_meta = col.get(where={"doc_id": doc_id}, include=["metadatas"])
            n_expected = {int((m or {}).get("n_chunks", -1)) for m in got_meta.get("metadatas") or []}
            if n_expected != {counts[doc_id]}:
                problems.append(f"index has a partial copy of {doc_id}")
    return problems
