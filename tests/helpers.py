"""Test doubles: no Ollama, no GPU, no downloaded models (spec §14)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import numpy as np

from ragsec.app import prompts
from ragsec.app.api import EvalDocs, create_app
from ragsec.app.chunking import approx_token_count
from ragsec.app.classifier import WindowedClassifier
from ragsec.app.clock import TurnClock
from ragsec.app.corpus import Document, load_corpus
from ragsec.app.index import VectorIndex
from ragsec.app.ingest import EvalRegistry, Ingestor
from ragsec.app.model_client import ModelOptions, ModelResult, ToolCall
from ragsec.app.modes import policy_for
from ragsec.app.pipeline import ModelMeta, Pipeline
from ragsec.app.render import TurnStore
from ragsec.app.retrieval import Retriever
from ragsec.app.tools import Outbox, PendingStore
from ragsec.app.turnlog import JsonlWriter
from ragsec.defenses.d2_output_handling import OutputHandler
from ragsec.defenses.d7_limits import RateLimiter
from ragsec.settings import AppConfig, Preset, load_app_config, load_dlp

ROOT = Path(__file__).resolve().parents[1]


STOPWORDS = set(
    "a an and are as at be by can do does for from get go has have how i if in into is it its me my no not of "
    "on or our out so that the their them then there these this to up us use was we what when where which who "
    "why will with you your".split()
)


class FakeEmbedder:
    """Deterministic hashed bag-of-words embeddings (stopwords dropped, sqrt term weights)."""

    dim = 256

    def _vec(self, text: str) -> list[float]:
        counts: dict[int, float] = {}
        for w in re.findall(r"[a-z0-9]+", text.lower()):
            if w in STOPWORDS or len(w) < 2:
                continue
            h = int(hashlib.md5(w.encode()).hexdigest(), 16) % self.dim
            counts[h] = counts.get(h, 0.0) + 1.0
        v = np.zeros(self.dim)
        for h, c in counts.items():
            v[h] = np.sqrt(c)
        n = np.linalg.norm(v)
        return (v / n if n else v + 1 / np.sqrt(self.dim)).tolist()

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._vec(text)

    def count_tokens(self, text: str) -> int:
        return approx_token_count(text)


class FakeClassifierBackend:
    """Flags windows containing a trigger word. Whitespace tokens."""

    def __init__(self, triggers: tuple[str, ...] = ("injectnow",)) -> None:
        self.vocab: list[str] = []
        self.index: dict[str, int] = {}
        self.triggers = triggers
        self.windows_scored: list[int] = []

    def encode(self, text: str) -> list[int]:
        ids = []
        for w in text.split():
            if w not in self.index:
                self.index[w] = len(self.vocab)
                self.vocab.append(w)
            ids.append(self.index[w])
        return ids

    def score_ids(self, ids: list[int]) -> float:
        self.windows_scored.append(len(ids))
        words = " ".join(self.vocab[i] for i in ids).lower()
        return 0.97 if any(t in words for t in self.triggers) else 0.02


def fake_classifier(threshold: float = 0.5) -> WindowedClassifier:
    return WindowedClassifier(FakeClassifierBackend(), max_tokens=512, window=448, stride=384, threshold=threshold)


@dataclass
class ScriptedChat:
    """A ChatModel that returns scripted results and records every call."""

    script: list[ModelResult] = field(default_factory=list)
    default: str = "Here is the answer [gen-vpn-setup]."
    calls: list[dict[str, Any]] = field(default_factory=list)
    model_name: str = "fake"

    def chat(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]], options: ModelOptions,
             deadline: float | None = None) -> ModelResult:
        self.calls.append({"messages": json.loads(json.dumps(messages)), "tools": tools, "options": options,
                           "deadline": deadline})
        if self.script:
            return self.script.pop(0)
        return ModelResult(content=self.default, done_reason="stop", prompt_eval_count=100, eval_count=20,
                           prompt_eval_seconds=0.1, eval_seconds=0.4)


def tool_result(*calls: tuple[str, dict[str, Any]], content: str = "") -> ModelResult:
    return ModelResult(content=content, tool_calls=[ToolCall(n, a) for n, a in calls], done_reason="stop",
                       prompt_eval_count=100, eval_count=10, prompt_eval_seconds=0.1, eval_seconds=0.2)


def ollama_lines(content: str, *, tool_calls: list[dict[str, Any]] | None = None, done_reason: str = "stop",
                 prompt_eval_count: int = 50, eval_count: int = 7, prompt_ns: int = 200_000_000,
                 eval_ns: int = 900_000_000) -> bytes:
    lines = []
    for piece in re.findall(r".{1,8}", content, re.DOTALL) or [""]:
        lines.append({"message": {"role": "assistant", "content": piece}, "done": False})
    if tool_calls:
        lines.append({"message": {"role": "assistant", "content": "", "tool_calls": tool_calls}, "done": False})
    lines.append({"message": {"role": "assistant", "content": ""}, "done": True, "done_reason": done_reason,
                  "prompt_eval_count": prompt_eval_count, "eval_count": eval_count,
                  "prompt_eval_duration": prompt_ns, "eval_duration": eval_ns, "load_duration": 5_000_000_000})
    return b"".join(json.dumps(x).encode() + b"\n" for x in lines)


class CountingTransport(httpx.MockTransport):
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.requests: list[dict[str, Any]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            self.requests.append(json.loads(request.content))
            return httpx.Response(status, content=body)

        super().__init__(handler)


def make_config(tmp: Path) -> AppConfig:
    cfg = load_app_config(root=ROOT)
    cfg.paths.chroma = str(tmp / "chroma")
    cfg.paths.logs = str(tmp / "logs")
    cfg.paths.generation_cache = str(tmp / "cache")
    return cfg


def corpus_docs() -> list[Document]:
    return load_corpus(ROOT / "data" / "corpus")


@dataclass
class Built:
    cfg: AppConfig
    preset: Preset
    pipeline: Pipeline
    app: Any
    index: VectorIndex
    collection: str
    chat: Any
    registry: EvalRegistry
    turn_store: TurnStore
    classifier: WindowedClassifier | None




def build_app(tmp: Path, preset: Preset | str = "baseline", *, mode: str = "eval", chat: Any | None = None,
              docs: list[Document] | None = None, classifier: WindowedClassifier | None = None,
              clock_factory: Any = TurnClock, limiter: RateLimiter | None = None) -> Built:
    from ragsec.settings import load_preset

    p = load_preset(preset, ROOT) if isinstance(preset, str) else preset
    cfg = make_config(tmp)
    embedder = FakeEmbedder()
    index = VectorIndex(cfg.path(cfg.paths.chroma), cfg.retrieval.hnsw)
    if p.needs_classifier and classifier is None:
        classifier = fake_classifier()
    collection = "test-corpus-d6" if p.d6_ingest_scan else "test-corpus"
    ingestor = Ingestor(embedder=embedder, index=index, chunking=cfg.chunking, classifier=classifier)
    if not index.has(collection):
        ingestor.build(collection, docs if docs is not None else corpus_docs(), d6=p.d6_ingest_scan,
                       threshold=cfg.classifier.threshold if p.d6_ingest_scan else None)
    chat = chat or ScriptedChat()
    policy = policy_for(mode)
    logs = cfg.path(cfg.paths.logs)
    handler = OutputHandler(cfg.d2, load_dlp(ROOT), prompts.fixed_instruction_text(cfg, d4=p.d4_spotlighting),
                            cfg.prompt.routing_code) if p.d2_output_handling else None
    if p.d7_limits and limiter is None:
        limiter = RateLimiter(cfg.d7.rate_per_minute, cfg.d7.max_in_flight)
    turn_store = TurnStore()
    pipeline = Pipeline(cfg=cfg, preset=p, policy=policy, model=ModelMeta("A", "fake", "sha256:fake", "0.0", False),
                        retriever=Retriever(embedder, index, collection), chat_model=chat, classifier=classifier,
                        output_handler=handler, outbox=Outbox(logs / "outbox.jsonl", "testtag"),
                        pending=PendingStore(), turnlog=JsonlWriter(logs / "turns.jsonl"), limiter=limiter,
                        turn_store=turn_store, run_tag="testtag", clock_factory=clock_factory)
    registry = EvalRegistry(cfg.path(cfg.paths.chroma) / "eval-registry.json")
    eval_docs = EvalDocs(ingestor, index, registry, collection, p.d6_ingest_scan,
                         frozenset(d.doc_id for d in (docs if docs is not None else corpus_docs())))
    app = create_app(cfg=cfg, preset=p, policy=policy, pipeline=pipeline, turn_store=turn_store,
                     eval_docs=eval_docs if policy.eval_endpoints else None, ui_dir=ROOT / "ui", model_slot="A")
    return Built(cfg, p, pipeline, app, index, collection, chat, registry, turn_store, classifier)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def trial_key_for(n: int) -> str:
    return hashlib.sha256(f"test|case|{n}".encode()).hexdigest()


def iter_lines(text: str) -> Iterator[str]:
    yield from text.splitlines()
