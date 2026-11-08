"""The RAG pipeline (spec §6.2). The baseline is vulnerable on purpose.

1. Retrieve the top 4 chunks by similarity, ignoring roles (D1 filters).
2. Build the system message (never contains document text).
3. Build one user message: chunks with header lines, then the question.
4. Call the model with the send_email tool: at most 3 model calls and 2
   executed tool calls per request; further tool-call attempts are counted and
   logged, never executed.
5. Return the answer (D2 applies to the delivered answer).

The code path is identical in every mode: the mode policy supplies the seed and
D4's markers and decides which clock D7's timeout uses; nothing here branches on
the mode itself.
"""

from __future__ import annotations

import re
import time
import traceback
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ragsec.app import prompts
from ragsec.app.classifier import WindowedClassifier
from ragsec.app.clock import TurnClock
from ragsec.app.index import RetrievedChunk
from ragsec.app.model_client import ChatModel, ModelOptions, ModelResult
from ragsec.app.modes import ModePolicy
from ragsec.app.render import TurnStore
from ragsec.app.retrieval import Retriever
from ragsec.app.tools import SEND_EMAIL_TOOL, Outbox, PendingAction, PendingStore, coerce_args
from ragsec.app.turnlog import JsonlWriter
from ragsec.defenses import d1_role_filter, d3_tool_gating, d5_classifier
from ragsec.defenses.d2_output_handling import OutputHandler
from ragsec.defenses.d7_limits import (
    STATUS_RATE,
    STATUS_TIMEOUT,
    STATUS_TOO_LONG,
    RateLimiter,
    message_too_long,
)
from ragsec.settings import AppConfig, Preset

OVERFLOW_ANSWER = "Sorry, that request is too long for me to answer."
_CITATION = re.compile(r"\[([a-z]{2,4}-[a-z0-9][a-z0-9-]*)\]")


@dataclass
class ChatRequest:
    role: str
    user_email: str
    message: str
    trial_key: str | None = None


@dataclass
class TurnResult:
    status: int
    body: dict[str, Any]


@dataclass
class ModelMeta:
    slot: str
    name: str
    digest: str
    ollama_version: str
    think: bool | None


class _Timeout(Exception):
    pass


@dataclass
class _Turn:
    turn_id: str
    req: ChatRequest
    clock: TurnClock
    events: list[dict[str, Any]] = field(default_factory=list)
    log: dict[str, Any] = field(default_factory=dict)
    pending: list[PendingAction] = field(default_factory=list)


class Pipeline:
    def __init__(
        self,
        *,
        cfg: AppConfig,
        preset: Preset,
        policy: ModePolicy,
        model: ModelMeta,
        retriever: Retriever,
        chat_model: ChatModel,
        classifier: WindowedClassifier | None,
        output_handler: OutputHandler | None,
        outbox: Outbox,
        pending: PendingStore,
        turnlog: JsonlWriter,
        limiter: RateLimiter | None,
        turn_store: TurnStore,
        run_tag: str,
        clock_factory: Callable[[], TurnClock] = TurnClock,
    ) -> None:
        if preset.needs_classifier and classifier is None:
            raise ValueError(f"preset {preset.name} needs the injection classifier")
        if preset.d2_output_handling and output_handler is None:
            raise ValueError("D2 is on but no output handler was provided")
        if preset.d7_limits and limiter is None:
            raise ValueError("D7 is on but no rate limiter was provided")
        self.cfg = cfg
        self.preset = preset
        self.policy = policy
        self.model = model
        self.retriever = retriever
        self.chat_model = chat_model
        self.classifier = classifier
        self.output_handler = output_handler
        self.outbox = outbox
        self.pending = pending
        self.turnlog = turnlog
        self.limiter = limiter
        self.turn_store = turn_store
        self.run_tag = run_tag
        self.clock_factory = clock_factory

    # ------------------------------------------------------------------ chat
    def handle_chat(self, req: ChatRequest) -> TurnResult:
        turn = _Turn(uuid.uuid4().hex, req, self.clock_factory())
        turn.log = self._base_log(turn)
        p = self.preset
        if p.d7_limits and message_too_long(req.message, self.cfg.d7.max_message_chars):
            turn.events.append({"type": "d7_message_too_long", "defense": "d7_limits",
                                "length": len(req.message), "limit": self.cfg.d7.max_message_chars})
            return self._finish(turn, STATUS_TOO_LONG, {"detail": "message too long"})
        acquired = False
        if p.d7_limits and self.limiter is not None:
            reason = self.limiter.try_acquire(req.user_email)
            if reason is not None:
                turn.events.append({"type": "d7_rate_limited", "defense": "d7_limits", "reason": reason})
                return self._finish(turn, STATUS_RATE, {"detail": f"rate limited ({reason})"})
            acquired = True
        try:
            return self._run(turn)
        except _Timeout:
            turn.events.append({"type": "d7_timeout", "defense": "d7_limits",
                                "limit_seconds": self.cfg.d7.timeout_seconds,
                                "clock": "virtual" if self.policy.virtual_timeout else "wall"})
            return self._finish(turn, STATUS_TIMEOUT, {"detail": "request timed out"})
        except Exception as exc:  # unhandled error: logged, returned as 500
            turn.log["error"] = f"{type(exc).__name__}: {exc}"
            turn.log["traceback"] = traceback.format_exc(limit=8)
            return self._finish(turn, 500, {"detail": "internal error"})
        finally:
            if acquired and self.limiter is not None:
                self.limiter.release(req.user_email)

    def _check_deadline(self, turn: _Turn) -> None:
        if not self.preset.d7_limits:
            return
        limit = self.cfg.d7.timeout_seconds
        if self.policy.virtual_timeout:
            if turn.clock.virtual_latency() > limit:
                raise _Timeout()
        elif turn.clock.wall_elapsed() > limit:
            raise _Timeout()

    def _run(self, turn: _Turn) -> TurnResult:
        req, p, cfg, clock = turn.req, self.preset, self.cfg, turn.clock
        seed = self.policy.seed(req.trial_key)
        marker = self.policy.d4_marker(req.trial_key) if p.d4_spotlighting else None
        turn.log["seed"] = seed
        turn.log["d4_marker_present"] = marker is not None

        # D5: screen the user message.
        if p.d5_classifier:
            assert self.classifier is not None
            with clock.stage("d5_message"):
                screen = d5_classifier.screen_message(self.classifier, req.message)
            turn.log["classifier_scores"]["message"] = round(screen.score, 6)
            if screen.flagged:
                turn.events.append({"type": "d5_blocked", "defense": "d5_classifier", "score": round(screen.score, 6)})
                return self._deliver(turn, cfg.d5.refusal, cfg.d5.refusal, [])

        # Retrieval.
        k = cfg.d5.candidates if p.d5_classifier else cfg.retrieval.top_k
        where = d1_role_filter.where_clause(req.role) if p.d1_role_filter else None
        with clock.stage("retrieve"):
            candidates = self.retriever.search(req.message, k, where)
        turn.log["retrieved_before"] = [_chunk_log(c) for c in candidates]
        if p.d5_classifier:
            assert self.classifier is not None
            with clock.stage("d5_chunks"):
                filt = d5_classifier.filter_chunks(self.classifier, candidates, cfg.d5.keep)
            chunks = filt.kept
            turn.log["classifier_scores"]["chunks"] = filt.scores
            for d in filt.dropped:
                turn.events.append({"type": "d5_chunk_dropped", "defense": "d5_classifier", **d})
        else:
            chunks = candidates[: cfg.retrieval.top_k]
        turn.log["retrieved_after"] = [_chunk_log(c) for c in chunks]
        self._check_deadline(turn)

        # Prompt.
        with clock.stage("build_prompt"):
            system = prompts.build_system_message(cfg, user_email=req.user_email, role=req.role,
                                                  d4=p.d4_spotlighting, marker=marker)
            user = prompts.build_user_message(chunks, req.message, d4=p.d4_spotlighting, marker=marker)
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": system.text},
            {"role": "user", "content": user},
        ]
        num_predict = cfg.d7.num_predict if p.d7_limits else cfg.generation.num_predict
        options = ModelOptions(
            temperature=cfg.generation.temperature,
            num_ctx=cfg.generation.num_ctx,
            num_predict=num_predict,
            seed=seed,
            think=self.model.think,
            truncate=cfg.generation.truncate,
            shift=cfg.generation.shift,
        )
        turn.log["est_prompt_tokens"] = sum(len(m["content"]) for m in messages) // 3
        turn.log["num_predict"] = num_predict

        # Model loop.
        deadline = None
        if p.d7_limits and not self.policy.virtual_timeout:
            deadline = time.perf_counter() + max(0.0, cfg.d7.timeout_seconds - clock.wall_elapsed())
        answer = ""
        executed = 0
        attempts = 0
        extra = 0
        overflow: str | None = None
        while turn.log["model_calls"] < cfg.limits.max_model_calls:
            self._check_deadline(turn)
            res = self.chat_model.chat(messages, [SEND_EMAIL_TOOL], options, deadline)
            turn.log["model_calls"] += 1
            clock.add_model_call(res.recorded_model_seconds, res.wall_seconds)
            turn.log["calls"].append(_call_log(res))
            if res.cache_hit:
                turn.log["cache_hits"] += 1
            if res.stream_closed_early:
                raise _Timeout()
            if res.context_overflow:
                overflow = res.context_overflow
                turn.events.append({"type": "context_overflow", "kind": overflow})
                answer = res.content if res.content.strip() else OVERFLOW_ANSWER
                break
            if not res.ok:
                raise RuntimeError(f"model call failed (HTTP {res.http_status}): {res.error}")
            answer = res.content
            self._check_deadline(turn)
            if not res.tool_calls:
                break
            messages.append(res.assistant_message())
            for tc in res.tool_calls:
                attempts += 1
                record: dict[str, Any] = {"name": tc.name, "arguments": tc.arguments}
                if executed >= cfg.limits.max_tool_calls:
                    extra += 1
                    record["executed"] = False
                    tool_text = "Not executed: the per-request tool-call limit was reached."
                elif tc.name != "send_email":
                    executed += 1
                    record["executed"] = False
                    tool_text = f"Unknown tool {tc.name!r}."
                else:
                    executed += 1
                    record["executed"] = True
                    with clock.stage("tool"):
                        tool_text, status = self._send_email(turn, tc.arguments)
                    record["status"] = status
                turn.log["tool_calls"].append(record)
                messages.append({"role": "tool", "tool_name": tc.name, "content": tool_text})
            self._check_deadline(turn)
        turn.log["tool_call_attempts"] = attempts
        turn.log["tool_calls_executed"] = executed
        turn.log["extra_tool_call_attempts"] = extra
        turn.log["context_overflow"] = overflow is not None
        turn.log["context_overflow_kind"] = overflow
        return self._deliver(turn, answer, None, chunks)

    def _send_email(self, turn: _Turn, args: dict[str, Any]) -> tuple[str, str]:
        req = turn.req
        to, subject, body = coerce_args(args)
        common: dict[str, Any] = {"trial_key": req.trial_key, "role": req.role, "requester": req.user_email,
                                  "to": to, "subject": subject, "body": body, "turn_id": turn.turn_id}
        if not self.preset.d3_tool_gating:
            self.outbox.record(status="sent", **common)
            turn.events.append({"type": "email_sent", "to": to})
            return f"Email sent to {to}.", "sent"
        ok, reason = d3_tool_gating.check_recipient(to, self.cfg.d3.allowed_domain)
        if not ok:
            self.outbox.record(status="blocked", reason=reason, **common)
            turn.events.append({"type": "d3_blocked", "defense": "d3_tool_gating", "to": to, "reason": reason})
            return f"Email not sent: {reason}.", "blocked"
        action = PendingAction(self.pending.new_action_id(), turn.turn_id, to, subject, body,
                               req.user_email, req.role, req.trial_key)
        self.pending.add(action)
        turn.pending.append(action)
        self.outbox.record(status="pending", action_id=action.action_id, **common)
        turn.events.append({"type": "d3_pending", "defense": "d3_tool_gating", "action_id": action.action_id, "to": to})
        return "The email is waiting for the user's confirmation and has not been sent yet.", "pending"

    def _deliver(self, turn: _Turn, raw_answer: str, fixed: str | None,
                 chunks: list[RetrievedChunk]) -> TurnResult:
        delivered = raw_answer
        if self.preset.d2_output_handling and fixed is None:
            assert self.output_handler is not None
            with turn.clock.stage("d2_output"):
                result = self.output_handler.apply(raw_answer, turn.req.role)
            delivered = result.text
            turn.events.extend(result.events)
        retrieved_ids = {c.doc_id for c in chunks}
        citations: list[str] = []
        for doc_id in _CITATION.findall(delivered):
            if doc_id in retrieved_ids and doc_id not in citations:
                citations.append(doc_id)
        turn.log["raw_answer"] = raw_answer
        turn.log["delivered_answer"] = delivered
        self.turn_store.put(turn.turn_id, delivered)
        body: dict[str, Any] = {"answer": delivered, "citations": citations}
        if turn.pending:
            body["pending_actions"] = [a.public() for a in turn.pending]
        return self._finish(turn, 200, body)

    def _finish(self, turn: _Turn, status: int, body: dict[str, Any]) -> TurnResult:
        body = {"turn_id": turn.turn_id, **body, "events": turn.events}
        turn.log["http_status"] = status
        turn.log["events"] = turn.events
        turn.log["output_tokens"] = sum(int(c.get("eval_count") or 0) for c in turn.log["calls"])
        turn.log["prompt_eval_count"] = sum(int(c.get("prompt_eval_count") or 0) for c in turn.log["calls"])
        turn.log["eval_count"] = turn.log["output_tokens"]
        turn.log["done_reason"] = turn.log["calls"][-1].get("done_reason") if turn.log["calls"] else None
        turn.log["timings"] = turn.clock.snapshot()
        turn.log["virtual_latency_seconds"] = round(turn.clock.virtual_latency(), 6)
        turn.log["finished_at"] = time.time()
        self.turnlog.write(turn.log)
        return TurnResult(status, body)

    def _base_log(self, turn: _Turn) -> dict[str, Any]:
        req = turn.req
        return {
            "turn_id": turn.turn_id,
            "run_tag": self.run_tag,
            "trial_key": req.trial_key,
            "mode": self.policy.mode.value,
            "model_slot": self.model.slot,
            "model": self.model.name,
            "model_digest": self.model.digest,
            "ollama_version": self.model.ollama_version,
            "preset": self.preset.name,
            "role": req.role,
            "user_email": req.user_email,
            "user_message": req.message,
            "started_at": time.time(),
            "retrieved_before": [],
            "retrieved_after": [],
            "classifier_scores": {},
            "calls": [],
            "model_calls": 0,
            "cache_hits": 0,
            "tool_calls": [],
            "tool_call_attempts": 0,
            "tool_calls_executed": 0,
            "extra_tool_call_attempts": 0,
            "context_overflow": False,
            "context_overflow_kind": None,
            "raw_answer": None,
            "delivered_answer": None,
            "error": None,
        }

    # --------------------------------------------------------------- confirm
    def confirm(self, turn_id: str, action_id: str, approve: bool) -> TurnResult:
        action = self.pending.pop(turn_id, action_id)
        if action is None:
            return TurnResult(404, {"detail": "no such pending action"})
        status = "sent" if approve else "cancelled"
        self.outbox.record(trial_key=action.trial_key, role=action.role, requester=action.requester, to=action.to,
                           subject=action.subject, body=action.body, status=status, turn_id=turn_id,
                           action_id=action_id)
        return TurnResult(200, {"action_id": action_id, "status": status})


def _chunk_log(c: RetrievedChunk) -> dict[str, Any]:
    return {"rank": c.rank, "chunk_id": c.chunk_id, "doc_id": c.doc_id, "tier": c.tier,
            "distance": round(c.distance, 6)}


def _call_log(res: ModelResult) -> dict[str, Any]:
    return {
        "cache_hit": res.cache_hit,
        "http_status": res.http_status,
        "done_reason": res.done_reason,
        "prompt_eval_count": res.prompt_eval_count,
        "eval_count": res.eval_count,
        "recorded_model_seconds": round(res.recorded_model_seconds, 6),
        "wall_seconds": round(res.wall_seconds, 6),
        "tool_calls": len(res.tool_calls),
        "context_overflow": res.context_overflow,
        "error": res.error,
    }
