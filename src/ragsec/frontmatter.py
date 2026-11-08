"""Minimal YAML front matter parsing for Markdown documents."""

from __future__ import annotations

from typing import Any

import yaml

from ragsec.textnorm import normalize_newlines


class FrontMatterError(ValueError):
    pass


def split(text: str) -> tuple[dict[str, Any], str]:
    """Return (front matter dict, body). Raises if the front matter is malformed."""
    text = normalize_newlines(text).lstrip("﻿")
    if not text.startswith("---\n"):
        raise FrontMatterError("document has no front matter (expected a leading '---' line)")
    end = text.find("\n---\n", 4)
    if end == -1:
        if text.endswith("\n---"):
            end = len(text) - 4
        else:
            raise FrontMatterError("front matter is not closed with a '---' line")
    raw = text[4:end]
    body = text[end + 5 :] if end + 5 <= len(text) else ""
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise FrontMatterError("front matter must be a YAML mapping")
    # YAML turns 2026-08-14 into a date; keep everything as plain strings.
    return {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in data.items()}, body


def join(meta: dict[str, Any], body: str) -> str:
    """Serialize front matter + body with stable key order."""
    lines = ["---"]
    for key, value in meta.items():
        if isinstance(value, list):
            lines.append(f"{key}: [{', '.join(str(v) for v in value)}]")
        else:
            lines.append(f"{key}: {value}")
    lines.append("---")
    return "\n".join(lines) + "\n" + body
