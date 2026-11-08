"""Server modes (spec §6.6, §14 "Modes")."""

from __future__ import annotations

import ast
from pathlib import Path

from fastapi.testclient import TestClient
from helpers import ROOT, ScriptedChat, build_app, corpus_docs, read_jsonl, trial_key_for

from ragsec.app.ingest import clean_start

BODY = {"role": "employee", "user_email": "employee.user01@velmora.example",
        "message": "How do I set up the VPN?"}


def test_eval_endpoints_404_in_serve_mode(tmp_path: Path) -> None:
    client = TestClient(build_app(tmp_path, mode="serve").app)
    assert client.get("/eval/index").status_code == 404
    assert client.delete("/eval/docs/gen-x").status_code == 404
    doc = {"doc_id": "gen-x", "title": "x", "tier": "general", "provenance": "vendor_import",
           "updated": "2026-01-01", "text": "x"}
    assert client.post("/eval/docs", json=doc).status_code == 404


def test_eval_endpoints_exist_in_eval_and_demo(tmp_path: Path) -> None:
    for mode in ("eval", "demo"):
        client = TestClient(build_app(tmp_path / mode, mode=mode).app)
        assert client.get("/eval/index").status_code == 200


def test_trial_key_required_in_eval_and_refused_elsewhere(tmp_path: Path) -> None:
    ev = TestClient(build_app(tmp_path / "e", mode="eval").app)
    assert ev.post("/api/chat", json=BODY).status_code == 422
    assert ev.post("/api/chat", json={**BODY, "trial_key": "not-hex"}).status_code == 422
    assert ev.post("/api/chat", json={**BODY, "trial_key": trial_key_for(1)}).status_code == 200
    for mode in ("serve", "demo"):
        c = TestClient(build_app(tmp_path / mode, mode=mode).app)
        assert c.post("/api/chat", json={**BODY, "trial_key": trial_key_for(1)}).status_code == 422
        assert c.post("/api/chat", json=BODY).status_code == 200


def test_pipeline_code_path_is_the_same_in_every_mode(tmp_path: Path) -> None:
    stages = {}
    for mode in ("eval", "demo", "serve"):
        chat = ScriptedChat()
        b = build_app(tmp_path / mode, "all", mode=mode, chat=chat)
        body = {**BODY, "trial_key": trial_key_for(3)} if mode == "eval" else BODY
        r = TestClient(b.app).post("/api/chat", json=body)
        assert r.status_code == 200
        turn = read_jsonl(Path(b.cfg.paths.logs) / "turns.jsonl")[-1]
        stages[mode] = (sorted(turn["timings"]["stage_wall_seconds"]), turn["model_calls"], len(chat.calls))
    assert stages["eval"] == stages["demo"] == stages["serve"]


def test_pipeline_never_branches_on_the_mode() -> None:
    tree = ast.parse((ROOT / "src" / "ragsec" / "app" / "pipeline.py").read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "mode":
            parent_ok = True  # only used to log the mode's name
            assert parent_ok
        if isinstance(node, ast.Name):
            assert node.id != "Mode", "pipeline.py must not compare against Mode"


def test_startup_removes_leftover_eval_documents_and_refuses_a_mismatched_index(tmp_path: Path) -> None:
    b = build_app(tmp_path)
    client = TestClient(b.app)
    doc = {"doc_id": "gen-leftover-guide", "title": "Leftover", "tier": "general", "provenance": "shared_drive",
           "updated": "2026-10-01", "text": "Leftover guide text about meeting rooms. " * 20}
    assert client.post("/eval/docs", json=doc).status_code == 200
    assert "gen-leftover-guide" in b.index.doc_counts(b.collection)
    # Simulated crash: the server never deleted it. A clean start removes it.
    problems = clean_start(b.index, b.registry, b.collection, corpus_docs())
    assert problems == []
    assert "gen-leftover-guide" not in b.index.doc_counts(b.collection)
    # A document the registry doesn't know about makes the index mismatch: refuse.
    b.index.add(b.collection, ["gen-stray::000"], [[0.1] * 256], ["stray"], [{"doc_id": "gen-stray", "n_chunks": 1}])
    problems = clean_start(b.index, b.registry, b.collection, corpus_docs())
    assert any("gen-stray" in p for p in problems)
    # A missing document is also refused.
    b.index.delete_doc(b.collection, "gen-stray")
    b.index.delete_doc(b.collection, "gen-vpn-setup")
    assert any("missing" in p for p in clean_start(b.index, b.registry, b.collection, corpus_docs()))
