"""Plain httpx client for Ollama's /api/chat with streaming (spec §4).

Every request field is explicit: ``truncate: false`` and ``shift: false`` on
every call, ``think: false`` for Model A (no ``think`` field for Model B),
``num_ctx`` set explicitly, and a per-trial seed.

Context overflow is classified from captured Ollama responses
(tests/fixtures/ollama/), never from guessed error text:
  * ``prompt_refused``: Ollama refused a prompt longer than num_ctx (an error
    response, a 400 in current releases);
  * ``context_filled``: generation ended because the context filled: a
    ``length`` stop with ``eval_count`` below ``num_predict``, or an error that
    names the context limit.
A ``length`` stop at ``num_predict`` is the output cap, not an overflow.
"""

from __future__ import annotations

import json
import re
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol

import httpx

from ragsec.app.cache import GenerationCache, cache_key


@dataclass(frozen=True)
class ModelOptions:
    temperature: float
    num_ctx: int
    num_predict: int
    seed: int
    think: bool | None
    truncate: bool = False
    shift: bool = False

    def cache_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ToolCall:
    name: str
    arguments: dict[str, Any]

    def as_message_part(self) -> dict[str, Any]:
        return {"function": {"name": self.name, "arguments": self.arguments}}


@dataclass
class ModelResult:
    content: str = ""
    tool_calls: list[ToolCall] = field(default_factory=list)
    done_reason: str | None = None
    prompt_eval_count: int | None = None
    eval_count: int | None = None
    prompt_eval_seconds: float = 0.0
    eval_seconds: float = 0.0
    http_status: int = 200
    error: str | None = None
    context_overflow: str | None = None
    cache_hit: bool = False
    wall_seconds: float = 0.0
    stream_closed_early: bool = False
    transport_error: bool = False

    @property
    def recorded_model_seconds(self) -> float:
        return self.prompt_eval_seconds + self.eval_seconds

    @property
    def ok(self) -> bool:
        return self.error is None and self.http_status == 200

    def assistant_message(self) -> dict[str, Any]:
        msg: dict[str, Any] = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [tc.as_message_part() for tc in self.tool_calls]
        return msg

    def to_cache_entry(self) -> dict[str, Any]:
        return {
            "content": self.content,
            "tool_calls": [{"name": t.name, "arguments": t.arguments} for t in self.tool_calls],
            "done_reason": self.done_reason,
            "prompt_eval_count": self.prompt_eval_count,
            "eval_count": self.eval_count,
            "prompt_eval_seconds": self.prompt_eval_seconds,
            "eval_seconds": self.eval_seconds,
            "http_status": self.http_status,
            "error": self.error,
            "context_overflow": self.context_overflow,
        }

    @classmethod
    def from_cache_entry(cls, entry: dict[str, Any]) -> ModelResult:
        return cls(
            content=entry.get("content", ""),
            tool_calls=[ToolCall(t["name"], dict(t.get("arguments") or {})) for t in entry.get("tool_calls", [])],
            done_reason=entry.get("done_reason"),
            prompt_eval_count=entry.get("prompt_eval_count"),
            eval_count=entry.get("eval_count"),
            prompt_eval_seconds=float(entry.get("prompt_eval_seconds", 0.0)),
            eval_seconds=float(entry.get("eval_seconds", 0.0)),
            http_status=int(entry.get("http_status", 200)),
            error=entry.get("error"),
            context_overflow=entry.get("context_overflow"),
            cache_hit=True,
        )


class ChatModel(Protocol):
    model_name: str

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        options: ModelOptions,
        deadline: float | None = None,
    ) -> ModelResult: ...


def classify_overflow(
    *,
    http_status: int,
    error: str | None,
    done_reason: str | None,
    eval_count: int | None,
    num_predict: int,
    refused_patterns: list[str],
    filled_patterns: list[str],
) -> str | None:
    """Return ``prompt_refused``, ``context_filled``, or None."""
    if error:
        if http_status >= 400 and any(re.search(p, error, re.IGNORECASE) for p in refused_patterns):
            return "prompt_refused"
        if any(re.search(p, error, re.IGNORECASE) for p in filled_patterns):
            return "context_filled"
        if any(re.search(p, error, re.IGNORECASE) for p in refused_patterns):
            return "prompt_refused"
    if done_reason == "length" and eval_count is not None and eval_count < num_predict:
        return "context_filled"
    return None


def _parse_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, dict) else {"_raw": raw}
        except json.JSONDecodeError:
            return {"_raw": raw}
    return {}


def _error_text(body: bytes) -> str:
    try:
        obj = json.loads(body.decode("utf-8", errors="replace"))
        if isinstance(obj, dict) and "error" in obj:
            return str(obj["error"])
    except json.JSONDecodeError:
        pass
    return body.decode("utf-8", errors="replace")[:2000]


class OllamaChatModel:
    """Streaming /api/chat client with the generation cache built in."""

    def __init__(
        self,
        *,
        base_url: str,
        model_name: str,
        keep_alive: str,
        model_digest: str,
        ollama_version: str,
        cache: GenerationCache | None,
        refused_patterns: list[str],
        filled_patterns: list[str],
        transport: httpx.BaseTransport | None = None,
        connect_timeout: float = 10.0,
        read_timeout: float = 900.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.model_name = model_name
        self.keep_alive = keep_alive
        self.model_digest = model_digest
        self.ollama_version = ollama_version
        self.cache = cache
        self.refused_patterns = refused_patterns
        self.filled_patterns = filled_patterns
        self._connect_timeout = connect_timeout
        self._client = httpx.Client(
            transport=transport,
            timeout=httpx.Timeout(connect=connect_timeout, read=read_timeout, write=60.0, pool=60.0),
        )

    def request_body(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]],
                     options: ModelOptions) -> dict[str, Any]:
        body: dict[str, Any] = {
            "model": self.model_name,
            "messages": messages,
            "stream": True,
            "keep_alive": self.keep_alive,
            "truncate": options.truncate,
            "shift": options.shift,
            "options": {
                "temperature": options.temperature,
                "num_ctx": options.num_ctx,
                "num_predict": options.num_predict,
                "seed": options.seed,
            },
        }
        if tools:
            body["tools"] = tools
        if options.think is not None:
            body["think"] = options.think
        return body

    def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        options: ModelOptions,
        deadline: float | None = None,
    ) -> ModelResult:
        key: str | None = None
        if self.cache is not None:
            key = cache_key(
                model_digest=self.model_digest,
                ollama_version=self.ollama_version,
                messages=messages,
                tools=tools,
                options=options.cache_dict(),
            )
            entry = self.cache.get(key)
            if entry is not None:
                return ModelResult.from_cache_entry(entry)
        t0 = time.perf_counter()
        result = self._stream(messages, tools, options, deadline)
        result.wall_seconds = time.perf_counter() - t0
        result.context_overflow = classify_overflow(
            http_status=result.http_status,
            error=result.error,
            done_reason=result.done_reason,
            eval_count=result.eval_count,
            num_predict=options.num_predict,
            refused_patterns=self.refused_patterns,
            filled_patterns=self.filled_patterns,
        )
        # Only complete generations (or deterministic refusals) are cached, so
        # cache entries are always complete (spec §10.2).
        if (
            self.cache is not None
            and key is not None
            and not result.transport_error
            and not result.stream_closed_early
            and (result.done_reason is not None or result.http_status >= 400)
        ):
            self.cache.put(key, result.to_cache_entry())
        return result

    def _stream(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        options: ModelOptions,
        deadline: float | None,
    ) -> ModelResult:
        body = self.request_body(messages, tools, options)
        result = ModelResult()
        parts: list[str] = []
        watchdog: threading.Timer | None = None
        timeout: httpx.Timeout | None = None
        if deadline is not None:
            # Ollama sends a queued request's headers only when it starts generating it,
            # so the wait in its queue must count against the deadline too: every phase of
            # the request gets at most the time left. Hanging up makes Ollama drop it.
            left = max(0.001, deadline - time.perf_counter())
            timeout = httpx.Timeout(connect=min(self._connect_timeout, left), read=left, write=min(60.0, left),
                                    pool=left)
        try:
            with self._client.stream("POST", f"{self.base_url}/api/chat", json=body,
                                     timeout=timeout if timeout is not None else httpx.USE_CLIENT_DEFAULT) as resp:
                result.http_status = resp.status_code
                if resp.status_code != 200:
                    result.error = _error_text(resp.read())
                    return result
                if deadline is not None:
                    remaining = max(0.0, deadline - time.perf_counter())
                    # Closing the response closes the stream, which makes Ollama
                    # stop generating (verified by `ragsec doctor`).
                    watchdog = threading.Timer(remaining, resp.close)
                    watchdog.daemon = True
                    watchdog.start()
                for line in resp.iter_lines():
                    if deadline is not None and time.perf_counter() >= deadline:
                        result.stream_closed_early = True
                        resp.close()
                        break
                    if not line:
                        continue
                    obj = json.loads(line)
                    if "error" in obj:
                        result.error = str(obj["error"])
                        break
                    msg = obj.get("message") or {}
                    if msg.get("content"):
                        parts.append(msg["content"])
                    for tc in msg.get("tool_calls") or []:
                        fn = tc.get("function") or {}
                        result.tool_calls.append(ToolCall(str(fn.get("name", "")), _parse_arguments(fn.get("arguments"))))
                    if obj.get("done"):
                        result.done_reason = obj.get("done_reason")
                        result.prompt_eval_count = obj.get("prompt_eval_count")
                        result.eval_count = obj.get("eval_count")
                        result.prompt_eval_seconds = (obj.get("prompt_eval_duration") or 0) / 1e9
                        result.eval_seconds = (obj.get("eval_duration") or 0) / 1e9
                        break
        except (httpx.StreamClosed, httpx.ReadError, httpx.RemoteProtocolError, httpx.TimeoutException) as exc:
            if deadline is not None and time.perf_counter() >= deadline - 0.05:
                result.stream_closed_early = True
            else:
                result.transport_error = True
                result.error = f"transport error: {exc}"
        except httpx.HTTPError as exc:
            result.transport_error = True
            result.error = f"transport error: {exc}"
        finally:
            if watchdog is not None:
                watchdog.cancel()
        if result.stream_closed_early and result.error is None:
            result.error = "stream closed at deadline"
        result.content = "".join(parts)
        return result

    def close(self) -> None:
        self._client.close()
