"""HTTP API (spec §6.1).

* ``POST /api/chat`` {role, user_email, message, trial_key?} → {turn_id, answer,
  citations, pending_actions?, events}. No other fields are accepted, so case IDs,
  trial numbers, and suite names can't reach the app (rule 3).
* ``POST /api/confirm`` {turn_id, action_id, approve}.
* ``GET /``, ``GET /render/{turn_id}``, ``GET /health``.
* Eval-only (eval and demo modes; 404 in serve mode): ``POST /eval/docs``,
  ``DELETE /eval/docs/{doc_id}``, ``GET /eval/index``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict

from ragsec.app import keys
from ragsec.app.corpus import PROVENANCES, Document
from ragsec.app.index import VectorIndex
from ragsec.app.ingest import EvalRegistry, Ingestor
from ragsec.app.modes import ModePolicy
from ragsec.app.pipeline import ChatRequest, Pipeline
from ragsec.app.render import TurnStore, render_page
from ragsec.settings import AppConfig, Preset

_DOC_ID = re.compile(r"^(gen|hr|adm)-[a-z0-9]+(?:-[a-z0-9]+)*$")


class ChatBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["employee", "hr", "it_admin"]
    user_email: str
    message: str
    trial_key: str | None = None


class ConfirmBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    turn_id: str
    action_id: str
    approve: bool


class EvalDocBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    doc_id: str
    title: str
    tier: Literal["general", "hr", "it_admin"]
    provenance: str
    updated: str
    text: str


@dataclass
class EvalDocs:
    """The eval-only ingest service. Keeps its own registry of what it added."""

    ingestor: Ingestor
    index: VectorIndex
    registry: EvalRegistry
    collection: str
    d6: bool
    corpus_doc_ids: frozenset[str]

    def add(self, body: EvalDocBody) -> tuple[int, dict[str, Any]]:
        if not _DOC_ID.fullmatch(body.doc_id):
            return 422, {"detail": "doc_id must look like a corpus doc_id (tier prefix and slug)"}
        if body.provenance not in PROVENANCES:
            return 422, {"detail": f"provenance must be one of {list(PROVENANCES)}"}
        if body.doc_id in self.corpus_doc_ids or body.doc_id in self.registry.entries(self.collection):
            return 409, {"detail": "doc_id already exists"}
        doc = Document.from_fields(doc_id=body.doc_id, title=body.title, tier=body.tier,
                                   provenance=body.provenance, updated=body.updated, text=body.text)
        # Record intent first, so a crash mid-ingest is still cleaned up at the next start.
        self.registry.add(self.collection, doc.doc_id, {"chunks": None, "quarantined": None})
        res = self.ingestor.ingest(self.collection, doc, d6=self.d6)
        self.registry.add(self.collection, doc.doc_id, {"chunks": res.chunks, "quarantined": res.quarantined})
        return 200, {"doc_id": doc.doc_id, "chunks": res.chunks, "quarantined": res.quarantined, "events": res.events}

    def delete(self, doc_id: str) -> tuple[int, dict[str, Any]]:
        if doc_id in self.corpus_doc_ids:
            return 403, {"detail": "corpus documents cannot be deleted through the eval endpoints"}
        info = self.registry.remove(self.collection, doc_id)
        removed = self.index.delete_doc(self.collection, doc_id)
        if info is None and removed == 0:
            return 404, {"detail": "unknown doc_id"}
        return 200, {"doc_id": doc_id, "removed_chunks": removed}

    def listing(self) -> dict[str, Any]:
        counts = self.index.doc_counts(self.collection)
        return {"collection": self.collection,
                "documents": [{"doc_id": k, "chunks": v} for k, v in sorted(counts.items())]}


def create_app(
    *,
    cfg: AppConfig,
    preset: Preset,
    policy: ModePolicy,
    pipeline: Pipeline,
    turn_store: TurnStore,
    eval_docs: EvalDocs | None,
    ui_dir: Path,
    model_slot: str,
) -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None, title="Vel")
    csp = cfg.d2.csp if preset.d2_output_handling else None

    def html_response(content: str, status: int = 200) -> HTMLResponse:
        resp = HTMLResponse(content, status_code=status)
        if csp:
            resp.headers["Content-Security-Policy"] = csp
        return resp

    @app.middleware("http")
    async def _csp_everywhere(request: Request, call_next: Any) -> Response:
        response: Response = await call_next(request)
        if csp and "Content-Security-Policy" not in response.headers:
            response.headers["Content-Security-Policy"] = csp
        return response

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "mode": policy.mode.value, "preset": preset.name, "model": model_slot}

    @app.post("/api/chat")
    def chat(body: ChatBody) -> JSONResponse:
        if body.trial_key is not None and not policy.trial_key_allowed:
            return JSONResponse({"detail": "trial_key is refused in this mode"}, status_code=422)
        if policy.trial_key_required:
            if body.trial_key is None:
                return JSONResponse({"detail": "trial_key is required in eval mode"}, status_code=422)
            if not keys.is_valid_trial_key(body.trial_key):
                return JSONResponse({"detail": "trial_key must be 64 lowercase hex characters"}, status_code=422)
        result = pipeline.handle_chat(ChatRequest(body.role, body.user_email, body.message, body.trial_key))
        return JSONResponse(result.body, status_code=result.status)

    @app.post("/api/confirm")
    def confirm(body: ConfirmBody) -> JSONResponse:
        result = pipeline.confirm(body.turn_id, body.action_id, body.approve)
        return JSONResponse(result.body, status_code=result.status)

    @app.get("/")
    def index() -> HTMLResponse:
        return html_response((ui_dir / "index.html").read_text(encoding="utf-8"))

    @app.get("/render/{turn_id}")
    def render(turn_id: str) -> HTMLResponse:
        answer = turn_store.get(turn_id)
        if answer is None:
            return html_response("<!doctype html><title>Not found</title><p>Unknown turn.</p>", 404)
        return html_response(render_page(answer))

    def _eval_guard() -> JSONResponse | None:
        if not policy.eval_endpoints or eval_docs is None:
            return JSONResponse({"detail": "Not Found"}, status_code=404)
        return None

    @app.post("/eval/docs")
    def eval_add(body: EvalDocBody) -> JSONResponse:
        if (blocked := _eval_guard()) is not None:
            return blocked
        assert eval_docs is not None
        status, payload = eval_docs.add(body)
        return JSONResponse(payload, status_code=status)

    @app.delete("/eval/docs/{doc_id}")
    def eval_delete(doc_id: str) -> JSONResponse:
        if (blocked := _eval_guard()) is not None:
            return blocked
        assert eval_docs is not None
        status, payload = eval_docs.delete(doc_id)
        return JSONResponse(payload, status_code=status)

    @app.get("/eval/index")
    def eval_index() -> JSONResponse:
        if (blocked := _eval_guard()) is not None:
            return blocked
        assert eval_docs is not None
        return JSONResponse(eval_docs.listing())

    app.mount("/static", StaticFiles(directory=str(ui_dir)), name="static")
    return app
