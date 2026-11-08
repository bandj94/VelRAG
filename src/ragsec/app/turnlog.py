"""Append-only JSON-lines logs (logs/turns.jsonl, logs/outbox.jsonl)."""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any


class JsonlWriter:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, record: dict[str, Any]) -> None:
        line = json.dumps(record, ensure_ascii=False, default=str)
        with self._lock, self.path.open("a", encoding="utf-8", newline="\n") as fh:
            fh.write(line + "\n")
            fh.flush()


class JsonlTailer:
    """Reads lines appended since the last call. Used by the harness."""

    def __init__(self, path: Path, from_end: bool = True) -> None:
        self.path = path
        self.offset = path.stat().st_size if (from_end and path.is_file()) else 0

    def read_new(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        out: list[dict[str, Any]] = []
        with self.path.open("rb") as fh:
            fh.seek(self.offset)
            data = fh.read()
        # Only consume complete lines.
        last_nl = data.rfind(b"\n")
        if last_nl == -1:
            return []
        chunk = data[: last_nl + 1]
        self.offset += len(chunk)
        for raw in chunk.decode("utf-8", errors="replace").splitlines():
            raw = raw.strip()
            if raw:
                try:
                    out.append(json.loads(raw))
                except json.JSONDecodeError:
                    continue
        return out
