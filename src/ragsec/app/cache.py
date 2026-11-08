"""Generation cache (spec §10.2). On in eval mode only. Never edit it by hand.

Every model call is keyed by a hash of the model digest, the Ollama version, the
full message list, the tool definitions, and the request options (seed,
num_predict, num_ctx, temperature, think, truncate, shift). A hit reuses the
stored response and its recorded model times.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def cache_key(
    *,
    model_digest: str,
    ollama_version: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    options: dict[str, Any],
) -> str:
    material = {
        "model_digest": model_digest,
        "ollama_version": ollama_version,
        "messages": messages,
        "tools": tools,
        "options": options,
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


class GenerationCache:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.hits = 0
        self.misses = 0

    def _path(self, key: str) -> Path:
        return self.directory / key[:2] / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        path = self._path(key)
        if not path.is_file():
            self.misses += 1
            return None
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            self.misses += 1
            return None
        self.hits += 1
        return entry if isinstance(entry, dict) else None

    def put(self, key: str, entry: dict[str, Any]) -> None:
        path = self._path(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".tmp-", suffix=".json")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(canonical_json(entry))
            os.replace(tmp, path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise
