"""Rule 3: the app can't see scoring data or trial labels (spec §14 "Integrity")."""

from __future__ import annotations

import ast
from pathlib import Path

from fastapi.testclient import TestClient
from helpers import ROOT, build_app, trial_key_for

APP_DIRS = [ROOT / "src" / "ragsec" / "app", ROOT / "src" / "ragsec" / "defenses"]
FORBIDDEN_TEXT = ["canaries.yaml", "facts.yaml", "directory.yaml", "data/corpus_src", "corpus_src",
                  "data/benign", "benign.yaml", "corpus_labels", "attacks/", "harness.yaml"]


def _py_files() -> list[Path]:
    return [p for d in APP_DIRS for p in d.rglob("*.py")]


def test_app_and_defenses_never_reference_scoring_data() -> None:
    for path in _py_files():
        text = path.read_text(encoding="utf-8")
        for token in FORBIDDEN_TEXT:
            assert token not in text, f"{path.relative_to(ROOT)} mentions {token!r}"


def test_app_and_defenses_never_import_the_harness() -> None:
    for path in _py_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                assert not name.startswith("ragsec.harness"), f"{path.name} imports {name}"


def test_retrieval_and_pipeline_never_read_the_eval_registry() -> None:
    for name in ("retrieval.py", "pipeline.py"):
        text = (ROOT / "src" / "ragsec" / "app" / name).read_text(encoding="utf-8")
        assert "EvalRegistry" not in text and "eval-registry" not in text and "registry" not in text.lower()


def test_chat_refuses_unknown_fields(tmp_path: Path) -> None:
    b = build_app(tmp_path)
    client = TestClient(b.app)
    body = {"role": "employee", "user_email": "employee.user01@velmora.example", "message": "hi",
            "trial_key": trial_key_for(1)}
    for extra in ({"case_id": "A3-007"}, {"trial": 2}, {"category": "x"}, {"suite": "dev"}, {"success": {}}):
        r = client.post("/api/chat", json={**body, **extra})
        assert r.status_code == 422, extra
    assert client.post("/api/chat", json=body).status_code == 200


def test_eval_docs_accepts_document_fields_only(tmp_path: Path) -> None:
    b = build_app(tmp_path)
    client = TestClient(b.app)
    doc = {"doc_id": "gen-new-guide", "title": "New guide", "tier": "general", "provenance": "vendor_import",
           "updated": "2026-10-01", "text": "Some helpful text about printers. " * 20}
    assert client.post("/eval/docs", json={**doc, "case_id": "A3-001"}).status_code == 422
    assert client.post("/eval/docs", json={**doc, "file": "attacks/docs/x.md"}).status_code == 422
    r = client.post("/eval/docs", json=doc)
    assert r.status_code == 200 and r.json()["quarantined"] is False
    assert {"doc_id", "chunks", "quarantined", "events"} <= set(r.json())
