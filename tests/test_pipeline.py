"""Pipeline smoke test with a mocked LLM, and the per-request call limits (spec §14)."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from helpers import ScriptedChat, build_app, corpus_docs, read_jsonl, tool_result, trial_key_for

from ragsec.app.model_client import ModelResult

EMP = "employee.user04@velmora.example"


def body(msg: str, n: int = 1) -> dict:
    return {"role": "employee", "user_email": EMP, "message": msg, "trial_key": trial_key_for(n)}


def test_pipeline_smoke(tmp_path: Path) -> None:
    chat = ScriptedChat([ModelResult(content="Use VelConnect with vpn.velmora.example [gen-vpn-setup] [gen-x].",
                                     done_reason="stop", eval_count=12, prompt_eval_count=900)])
    docs = [d for d in corpus_docs() if d.doc_id in ("gen-vpn-setup", "gen-pto-policy")]
    b = build_app(tmp_path, chat=chat, docs=docs)
    r = TestClient(b.app).post("/api/chat", json=body("How do I set up the VPN?"))
    data = r.json()
    assert r.status_code == 200
    assert data["answer"].startswith("Use VelConnect")
    assert data["citations"] == ["gen-vpn-setup"]
    assert "pending_actions" not in data
    turn = read_jsonl(Path(b.cfg.paths.logs) / "turns.jsonl")[-1]
    for field in ("run_tag", "trial_key", "mode", "model", "model_digest", "ollama_version", "preset", "role",
                  "user_email", "user_message", "retrieved_before", "retrieved_after", "classifier_scores",
                  "est_prompt_tokens", "prompt_eval_count", "eval_count", "done_reason", "context_overflow",
                  "context_overflow_kind", "model_calls", "cache_hits", "tool_calls", "extra_tool_call_attempts",
                  "raw_answer", "delivered_answer", "events", "http_status", "timings", "virtual_latency_seconds",
                  "error"):
        assert field in turn, field
    assert len(turn["retrieved_after"]) == 4
    assert TestClient(b.app).get(f"/render/{data['turn_id']}").status_code == 200


def test_at_most_three_model_calls_and_two_executed_tool_calls(tmp_path: Path) -> None:
    email = ("send_email", {"to": EMP, "subject": "s", "body": "b"})
    chat = ScriptedChat([tool_result(email, email), tool_result(email), tool_result(email),
                         ModelResult(content="never reached")])
    b = build_app(tmp_path, chat=chat)
    r = TestClient(b.app).post("/api/chat", json=body("Email me things"))
    assert r.status_code == 200
    turn = read_jsonl(Path(b.cfg.paths.logs) / "turns.jsonl")[-1]
    assert turn["model_calls"] == 3 and len(chat.calls) == 3
    assert turn["tool_calls_executed"] == 2
    assert turn["tool_call_attempts"] == 4 and turn["extra_tool_call_attempts"] == 2
    assert len(read_jsonl(Path(b.cfg.paths.logs) / "outbox.jsonl")) == 2
    # tool results go back to the model as tool messages
    assert chat.calls[1]["messages"][-1]["role"] == "tool"


def test_context_overflow_is_a_normal_answer_with_an_event(tmp_path: Path) -> None:
    chat = ScriptedChat([ModelResult(http_status=400, error="request exceeds the available context size",
                                     context_overflow="prompt_refused")])
    b = build_app(tmp_path, chat=chat)
    r = TestClient(b.app).post("/api/chat", json=body("x " * 10))
    assert r.status_code == 200
    assert any(e["type"] == "context_overflow" for e in r.json()["events"])
    assert read_jsonl(Path(b.cfg.paths.logs) / "turns.jsonl")[-1]["context_overflow_kind"] == "prompt_refused"


def test_model_errors_become_logged_500s(tmp_path: Path) -> None:
    chat = ScriptedChat([ModelResult(http_status=500, error="boom")])
    b = build_app(tmp_path, chat=chat)
    r = TestClient(b.app).post("/api/chat", json=body("hi"))
    assert r.status_code == 500
    assert "boom" in read_jsonl(Path(b.cfg.paths.logs) / "turns.jsonl")[-1]["error"]
