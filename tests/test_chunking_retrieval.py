"""Chunking and retrieval (spec §14).

The checks against the real tokenizers and the real embedder need model files,
so they run locally before each freeze and are skipped in CI.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest
from helpers import ROOT, corpus_docs

from ragsec.app import integrity
from ragsec.app.chunking import approx_token_count, chunk_text
from ragsec.app.index import VectorIndex
from ragsec.harness.data import load_benign
from ragsec.settings import HnswCfg, load_app_config, load_pins


def test_chunks_respect_limits_and_cover_the_document() -> None:
    for d in corpus_docs():
        chunks = chunk_text(d.text, approx_token_count, target=400, overlap=50, max_tokens=512)
        assert chunks
        assert all(c.n_tokens <= 512 for c in chunks)
        joined = "\n".join(c.text for c in chunks)
        for line in d.text.splitlines():
            if line.strip():
                assert line.strip() in joined, (d.doc_id, line)
        for prev, nxt in zip(chunks, chunks[1:], strict=False):
            # consecutive chunks overlap: the next chunk starts with text from the end of the previous one
            opening = nxt.text.split("\n")[0].strip()
            assert opening and opening in prev.text, (d.doc_id, opening)


def test_long_unbroken_text_is_split() -> None:
    text = " ".join(["word"] * 3000)
    chunks = chunk_text(text, approx_token_count, target=400, overlap=50, max_tokens=512)
    assert len(chunks) > 5 and all(c.n_tokens <= 512 for c in chunks)


def test_chroma_search_matches_brute_force_cosine(tmp_path: Path) -> None:
    rng = np.random.default_rng(0)
    n, dim = 150, 48
    vecs = rng.normal(size=(n, dim))
    vecs /= np.linalg.norm(vecs, axis=1, keepdims=True)
    index = VectorIndex(tmp_path / "chroma", HnswCfg())
    index.recreate("bf-test")
    index.add("bf-test", [f"c{i}" for i in range(n)], vecs.tolist(), [f"t{i}" for i in range(n)],
              [{"doc_id": f"d{i}", "tier": "general"} for i in range(n)])
    for _ in range(40):
        q = rng.normal(size=dim)
        q /= np.linalg.norm(q)
        got = [c.chunk_id for c in index.query("bf-test", q.tolist(), 4)]
        expected = [f"c{i}" for i in np.argsort(-(vecs @ q))[:4]]
        assert got == expected


def _local_model_dirs() -> tuple[Path | None, Path | None]:
    cfg = load_app_config()
    pins = load_pins()
    hf = cfg.path(cfg.paths.hf_home)
    out: list[Path | None] = []
    for key in ("embeddings", cfg.classifier.pin_key):
        pin = pins.huggingface.get(key)
        d = integrity.hf_snapshot_dir(hf, pin.repo, pin.revision) if pin and pin.revision else None
        out.append(d if d is not None and d.is_dir() else None)
    return out[0], out[1]


@pytest.mark.local_models
def test_chunks_fit_both_real_tokenizers() -> None:
    emb_dir, clf_dir = _local_model_dirs()
    if emb_dir is None or clf_dir is None:
        pytest.skip("needs the embedding model and the classifier downloaded (local only)")
    from transformers import AutoTokenizer

    emb_tok = AutoTokenizer.from_pretrained(str(emb_dir), local_files_only=True)
    clf_tok = AutoTokenizer.from_pretrained(str(clf_dir), local_files_only=True)

    def count(tok: object, text: str) -> int:
        return len(tok(text, add_special_tokens=True, truncation=False)["input_ids"])  # type: ignore[operator]

    cfg = load_app_config()
    for d in corpus_docs():
        for c in chunk_text(d.text, lambda t: count(emb_tok, t), target=cfg.chunking.target_tokens,
                            overlap=cfg.chunking.overlap_tokens, max_tokens=cfg.chunking.max_tokens):
            assert count(emb_tok, c.text) <= 512
            assert count(clf_tok, c.text) <= 512, (d.doc_id, c.index)


@pytest.mark.local_models
def test_real_retrieval_matches_brute_force_for_benign_questions(tmp_path: Path) -> None:
    emb_dir, _ = _local_model_dirs()
    if emb_dir is None:
        pytest.skip("needs the embedding model downloaded (local only)")
    from ragsec.app.embeddings import BgeEmbedder
    from ragsec.app.ingest import Ingestor

    cfg = load_app_config()
    emb = BgeEmbedder(emb_dir, query_instruction=cfg.embeddings.query_instruction)
    index = VectorIndex(tmp_path / "chroma", cfg.retrieval.hnsw)
    Ingestor(embedder=emb, index=index, chunking=cfg.chunking).build("real-test", corpus_docs(), d6=False)
    ids, embs, _ = index.all_embeddings("real-test")
    mat = np.array(embs)
    for case in load_benign(ROOT / "data" / "benign" / "benign.yaml"):
        q = np.array(emb.embed_query(case["user_message"]))
        expected = [ids[i] for i in np.argsort(-(mat @ q))[:4]]
        got = [c.chunk_id for c in index.query("real-test", q.tolist(), 4)]
        assert got == expected, case["id"]
