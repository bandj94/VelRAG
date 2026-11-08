"""Build the real components and run the server (``ragsec serve``).

One server process serves one preset and one model, fixed at startup (§6.6).
"""

from __future__ import annotations

import sys
import threading
from dataclasses import dataclass
from pathlib import Path

from fastapi import FastAPI

from ragsec import paths
from ragsec.app import integrity, prompts
from ragsec.app.api import EvalDocs, create_app
from ragsec.app.cache import GenerationCache
from ragsec.app.classifier import HFClassifierBackend, WindowedClassifier
from ragsec.app.corpus import load_corpus
from ragsec.app.embeddings import BgeEmbedder
from ragsec.app.index import VectorIndex
from ragsec.app.ingest import EvalRegistry, Ingestor, clean_start
from ragsec.app.model_client import OllamaChatModel
from ragsec.app.modes import Mode, policy_for
from ragsec.app.pipeline import ModelMeta, Pipeline
from ragsec.app.render import TurnStore
from ragsec.app.retrieval import Retriever
from ragsec.app.tools import Outbox, PendingStore
from ragsec.app.turnlog import JsonlWriter
from ragsec.defenses import d6_ingest_scan
from ragsec.defenses.d2_output_handling import OutputHandler
from ragsec.defenses.d7_limits import RateLimiter
from ragsec.settings import (
    AppConfig,
    Pins,
    Preset,
    load_app_config,
    load_dlp,
    load_pins,
    load_preset,
)


class StartupError(RuntimeError):
    pass


@dataclass
class Built:
    app: FastAPI
    cfg: AppConfig
    preset: Preset
    collection: str


def active_collection(cfg: AppConfig, preset: Preset) -> str:
    if preset.d6_ingest_scan:
        return d6_ingest_scan.collection_name(cfg.retrieval.d6_collection_prefix, cfg.classifier.threshold)
    return cfg.retrieval.collection


def load_classifier(cfg: AppConfig, model_dir: Path) -> WindowedClassifier:
    c = cfg.classifier
    backend = HFClassifierBackend(model_dir, c.active_model.malicious_label_index)
    return WindowedClassifier(backend, max_tokens=c.max_tokens, window=c.window_tokens,
                              stride=c.stride_tokens, threshold=c.threshold, name=c.active_model.repo)


def build(*, mode: str, preset_name: str, slot: str, run_tag: str, root: Path | None = None,
          cfg: AppConfig | None = None, pins: Pins | None = None) -> Built:
    root = root or paths.repo_root()
    cfg = cfg or load_app_config(root=root)
    pins = pins or load_pins(root=root)
    preset = load_preset(preset_name, root)
    policy = policy_for(Mode(mode))

    report = integrity.startup_check(cfg, pins, slot=slot, need_classifier=preset.needs_classifier)
    for w in report.warnings:
        print(f"[integrity] warning: {w}", file=sys.stderr)
    if not report.ok:
        raise StartupError("startup integrity check failed:\n  " + "\n  ".join(report.errors))

    emb_cfg = cfg.embeddings
    embedder = BgeEmbedder(Path(str(report.details["embeddings_dir"])), device=emb_cfg.device,
                           batch_size=emb_cfg.batch_size, max_tokens=emb_cfg.max_tokens,
                           query_instruction=emb_cfg.query_instruction)
    classifier = None
    if preset.needs_classifier:
        classifier = load_classifier(cfg, Path(str(report.details["classifier_dir"])))

    index = VectorIndex(cfg.path(cfg.paths.chroma), cfg.retrieval.hnsw)
    collection = active_collection(cfg, preset)
    registry = EvalRegistry(cfg.path(cfg.paths.chroma) / "eval-registry.json")
    corpus = load_corpus(cfg.path(cfg.paths.corpus))
    if policy.eval_endpoints:
        problems = clean_start(index, registry, collection, corpus)
        if problems:
            raise StartupError("the active index does not hold exactly the clean corpus:\n  " + "\n  ".join(problems))
    elif not index.has(collection):
        raise StartupError(f"collection {collection!r} does not exist; run `ragsec ingest`")

    logs = cfg.path(cfg.paths.logs)
    model_cfg = cfg.model(slot)
    digest = str(report.details.get("model_digest", ""))
    version = str(report.details.get("ollama_version", ""))
    cache = GenerationCache(cfg.path(cfg.paths.generation_cache)) if policy.cache_enabled else None
    chat_model = OllamaChatModel(
        base_url=cfg.ollama.url, model_name=model_cfg.name, keep_alive=cfg.ollama.keep_alive,
        model_digest=digest, ollama_version=version, cache=cache,
        refused_patterns=cfg.ollama.prompt_refused_error_patterns,
        filled_patterns=cfg.ollama.context_filled_error_patterns,
    )
    output_handler = None
    if preset.d2_output_handling:
        output_handler = OutputHandler(cfg.d2, load_dlp(root),
                                       prompts.fixed_instruction_text(cfg, d4=preset.d4_spotlighting),
                                       cfg.prompt.routing_code)
    limiter = RateLimiter(cfg.d7.rate_per_minute, cfg.d7.max_in_flight) if preset.d7_limits else None
    turn_store = TurnStore()
    pipeline = Pipeline(
        cfg=cfg, preset=preset, policy=policy,
        model=ModelMeta(slot, model_cfg.name, digest, version, model_cfg.think),
        retriever=Retriever(embedder, index, collection), chat_model=chat_model, classifier=classifier,
        output_handler=output_handler, outbox=Outbox(logs / "outbox.jsonl", run_tag), pending=PendingStore(),
        turnlog=JsonlWriter(logs / "turns.jsonl"), limiter=limiter, turn_store=turn_store, run_tag=run_tag,
    )
    eval_docs = None
    if policy.eval_endpoints:
        ingestor = Ingestor(embedder=embedder, index=index, chunking=cfg.chunking, classifier=classifier)
        eval_docs = EvalDocs(ingestor, index, registry, collection, preset.d6_ingest_scan,
                             frozenset(d.doc_id for d in corpus))
    app = create_app(cfg=cfg, preset=preset, policy=policy, pipeline=pipeline, turn_store=turn_store,
                     eval_docs=eval_docs, ui_dir=cfg.path(cfg.paths.ui), model_slot=slot)
    return Built(app, cfg, preset, collection)


def run(*, mode: str, preset_name: str, slot: str, run_tag: str, port: int | None = None,
        with_attacker_server: bool = True) -> None:
    import uvicorn

    from ragsec import attacker_server

    built = build(mode=mode, preset_name=preset_name, slot=slot, run_tag=run_tag)
    cfg = built.cfg
    if with_attacker_server:
        try:
            srv = attacker_server.make_server(cfg.attacker_server.host, cfg.attacker_server.port,
                                              cfg.path(cfg.paths.logs) / "attacker.jsonl")
            threading.Thread(target=srv.serve_forever, daemon=True, name="attacker-server").start()
        except OSError as exc:
            print(f"[serve] attacker server not started ({exc}); is another one running?", file=sys.stderr)
    host = cfg.server.host
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise StartupError("rule 9: the app must bind to 127.0.0.1 only")
    print(f"[serve] mode={mode} preset={built.preset.name} model={slot} collection={built.collection} "
          f"http://{host}:{port or cfg.server.port}", flush=True)
    uvicorn.run(built.app, host=host, port=port or cfg.server.port, log_level="warning")
