"""Context overflow on captured fixtures, the generation cache with the virtual
clock, trial keys, and freeze checks (spec §14)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from helpers import ROOT, CountingTransport, build_app, ollama_lines, read_jsonl

from ragsec.app import keys as app_keys
from ragsec.app.cache import GenerationCache, cache_key
from ragsec.app.model_client import ModelOptions, OllamaChatModel, classify_overflow
from ragsec.app.modes import policy_for
from ragsec.harness import freeze
from ragsec.harness import keys as h_keys
from ragsec.settings import load_app_config

FIXTURES = ROOT / "tests" / "fixtures" / "ollama"


def _fixture(name: str) -> dict:
    path = FIXTURES / f"{name}.json"
    if not path.is_file():
        pytest.skip(f"{path.name} not captured yet (run `ragsec doctor`)")
    return json.loads(path.read_text(encoding="utf-8"))


def _classify(fx: dict) -> str | None:
    cfg = load_app_config()
    body = fx["body"]
    return classify_overflow(http_status=fx["status"], error=body.get("error"), done_reason=body.get("done_reason"),
                             eval_count=body.get("eval_count"), num_predict=fx["request"]["num_predict"],
                             refused_patterns=cfg.ollama.prompt_refused_error_patterns,
                             filled_patterns=cfg.ollama.context_filled_error_patterns)


def test_refused_prompt_counts_as_overflow() -> None:
    assert _classify(_fixture("prompt_refused")) == "prompt_refused"


def test_context_filled_generation_counts_as_overflow() -> None:
    assert _classify(_fixture("context_filled")) == "context_filled"


def test_num_predict_stop_is_not_an_overflow() -> None:
    assert _classify(_fixture("num_predict_stop")) is None


# ------------------------------------------------------------------- cache
OPTS = ModelOptions(temperature=0.7, num_ctx=8192, num_predict=4096, seed=7, think=False)
MSGS = [{"role": "system", "content": "s"}, {"role": "user", "content": "u"}]
TOOLS = [{"type": "function", "function": {"name": "send_email"}}]


def test_same_key_hits_and_any_change_misses() -> None:
    base = cache_key(model_digest="d", ollama_version="v", messages=MSGS, tools=TOOLS, options=OPTS.cache_dict())
    assert base == cache_key(model_digest="d", ollama_version="v", messages=list(MSGS), tools=TOOLS,
                             options=OPTS.cache_dict())
    variants = [
        dict(model_digest="d2", ollama_version="v", messages=MSGS, tools=TOOLS, options=OPTS.cache_dict()),
        dict(model_digest="d", ollama_version="v2", messages=MSGS, tools=TOOLS, options=OPTS.cache_dict()),
        dict(model_digest="d", ollama_version="v", messages=[*MSGS, {"role": "user", "content": "x"}], tools=TOOLS,
             options=OPTS.cache_dict()),
        dict(model_digest="d", ollama_version="v", messages=MSGS, tools=[], options=OPTS.cache_dict()),
    ]
    for field in ("seed", "num_predict", "num_ctx", "temperature", "think", "truncate", "shift"):
        opts = OPTS.cache_dict()
        opts[field] = {"seed": 8, "num_predict": 512, "num_ctx": 4096, "temperature": 0.1, "think": None,
                       "truncate": True, "shift": True}[field]
        variants.append(dict(model_digest="d", ollama_version="v", messages=MSGS, tools=TOOLS, options=opts))
    for v in variants:
        assert cache_key(**v) != base  # type: ignore[arg-type]


def _client(tmp: Path, transport: CountingTransport) -> OllamaChatModel:
    return OllamaChatModel(base_url="http://ollama.test", model_name="m", keep_alive="30m", model_digest="dig",
                           ollama_version="0.40.15", cache=GenerationCache(tmp / "cache"), refused_patterns=[],
                           filled_patterns=[], transport=transport)


def test_hit_reproduces_recorded_model_times(tmp_path: Path) -> None:
    transport = CountingTransport(ollama_lines("hello there", prompt_ns=300_000_000, eval_ns=1_700_000_000))
    client = _client(tmp_path, transport)
    first = client.chat(MSGS, TOOLS, OPTS)
    second = client.chat(MSGS, TOOLS, OPTS)
    assert len(transport.requests) == 1
    assert not first.cache_hit and second.cache_hit
    assert second.content == first.content == "hello there"
    assert second.recorded_model_seconds == pytest.approx(first.recorded_model_seconds) == pytest.approx(2.0)


def test_request_fields_are_explicit(tmp_path: Path) -> None:
    transport = CountingTransport(ollama_lines("x"))
    _client(tmp_path, transport).chat(MSGS, TOOLS, OPTS)
    body = transport.requests[0]
    assert body["truncate"] is False and body["shift"] is False and body["think"] is False
    assert body["options"] == {"temperature": 0.7, "num_ctx": 8192, "num_predict": 4096, "seed": 7}
    assert body["stream"] is True and body["keep_alive"] == "30m"
    nothink = ModelOptions(temperature=0.7, num_ctx=8192, num_predict=4096, seed=7, think=None)
    _client(tmp_path / "b", transport).chat(MSGS, TOOLS, nothink)
    assert "think" not in transport.requests[1]


def test_d2_on_and_off_share_generations_and_virtual_latency(tmp_path: Path) -> None:
    transport = CountingTransport(ollama_lines("Use VelConnect [gen-vpn-setup]."))
    results = {}
    for preset in ("baseline", "d2"):
        chat = OllamaChatModel(base_url="http://ollama.test", model_name="m", keep_alive="30m", model_digest="dig",
                               ollama_version="0.40.15", cache=GenerationCache(tmp_path / "shared-cache"),
                               refused_patterns=[], filled_patterns=[], transport=transport)
        b = build_app(tmp_path / preset, preset, chat=chat)
        r = TestClient(b.app).post("/api/chat", json={"role": "employee", "user_email": "employee.user02@velmora.example",
                                                      "message": "How do I set up the VPN?",
                                                      "trial_key": h_keys.trial_key("frozen-v1", "B-001", 0)})
        assert r.status_code == 200
        results[preset] = read_jsonl(Path(b.cfg.paths.logs) / "turns.jsonl")[-1]
    assert len(transport.requests) == 1  # D2 reused baseline's generation
    assert results["d2"]["cache_hits"] == 1
    assert results["d2"]["timings"]["model_recorded_seconds"] == results["baseline"]["timings"]["model_recorded_seconds"]


# -------------------------------------------------------------- trial keys
def test_same_trial_same_key_seed_marker_user_in_every_preset() -> None:
    pool = [f"employee.user{i:02d}@velmora.example" for i in range(1, 11)]
    k1 = h_keys.trial_key("frozen-v1", "A3-007", 1)
    k2 = h_keys.trial_key("frozen-v1", "A3-007", 1)
    assert k1 == k2
    ev = policy_for("eval")
    assert ev.seed(k1) == ev.seed(k2) and ev.d4_marker(k1) == ev.d4_marker(k2)
    assert h_keys.pick_user(pool, k1) == h_keys.pick_user(pool, k2)
    other = h_keys.trial_key("adaptive-final", "A3-007", 1)
    assert other != k1
    assert ev.seed(other) != ev.seed(k1)
    assert ev.d4_marker(other) != ev.d4_marker(k1)
    users = {h_keys.pick_user(pool, h_keys.trial_key(ns, "A3-007", 1)) for ns in
             ("frozen-v1", "adaptive-final", "candidates", "adaptive-dev", "benign-v1")}
    assert len(users) > 1
    assert app_keys.is_valid_trial_key(k1)


# ------------------------------------------------------------------- freeze
def test_harness_refuses_when_a_frozen_hash_does_not_match(tmp_path: Path) -> None:
    (tmp_path / "data" / "benign").mkdir(parents=True)
    f = tmp_path / "data" / "benign" / "benign.yaml"
    f.write_text("- id: B-001\n", encoding="utf-8")
    (tmp_path / "FREEZE.md").write_text("# FREEZE\n", encoding="utf-8")
    freeze.add_entry("data/benign/benign.yaml", "benign-v1", "draft", "", tmp_path)
    assert freeze.verify("data/benign/benign.yaml", tmp_path).version == "benign-v1"
    f.write_text("- id: B-001\n- id: B-002\n", encoding="utf-8")
    with pytest.raises(freeze.FreezeError):
        freeze.verify("data/benign/benign.yaml", tmp_path)
    with pytest.raises(freeze.FreezeError):
        freeze.verify("attacks/frozen/dev.yaml", tmp_path)
