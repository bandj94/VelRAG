"""Predictions files (spec rule 15, §10.4, §16).

The predictions files stay outside the repository folder until their scoring
steps. Only ``ragsec report`` reads them, after verifying the SHA-256 committed in
``PREDICTIONS.sha256`` (case-insensitive hex). Tests use a fixture file only.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

ATTACK_ROWS = ("D1", "D2", "D3", "D4", "D5", "D6", "D7", "All")
ATTACK_COLS = ("A1", "A2", "A3", "A4", "A5", "A6", "A7", "A8")
BENIGN_COL = "Benign accuracy"
REFUSAL_COL = "False refusals"
ALLOWED_ATTACK = {"stops", "reduces", "none"}
ALLOWED_BENIGN = {"up", "same", "down a little", "down a lot"}
ALLOWED_REFUSAL = {"down", "same", "up a little", "up a lot"}
POISON_ITEMS = (
    "Link payload, 1,000 examples: smallest count above 50%",
    "Link payload, 4,000 examples: smallest count above 50%",
    "Advice payload, 1,000 examples: smallest count above 50%",
    "Advice payload, 4,000 examples: smallest count above 50%",
    "Count or share",
    "Clean accuracy at 50 poisoned examples",
)
ALLOWED_COUNT = {"10", "25", "50", "not even at 50"}
ALLOWED_DRIVER = {"count", "share", "unclear"}
PRESET_FOR_ROW = {"D1": "d1", "D2": "d2", "D3": "d3", "D4": "d4", "D5": "d5", "D6": "d6", "D7": "d7", "All": "all"}

# Cells that hold because the defense removes exactly what the check looks for (§10.4).
BY_DESIGN_CELLS = {("D1", "A4"), ("D2", "A2"), ("D2", "A3"), ("D2", "A6"),
                   ("All", "A2"), ("All", "A3"), ("All", "A4"), ("All", "A6")}
BY_DESIGN_VIGILANT = {("D3", "A7"), ("All", "A7")}


class PredictionHashError(RuntimeError):
    pass


class PredictionParseError(ValueError):
    pass


@dataclass
class Predictions:
    attack: dict[tuple[str, str], str] = field(default_factory=dict)
    poisoning: dict[str, str] = field(default_factory=dict)
    todo: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


def read_expected_hash(sha_path: Path) -> str:
    text = sha_path.read_text(encoding="utf-8-sig", errors="replace")
    m = re.search(r"\b([0-9a-fA-F]{64})\b", text)
    if not m:
        raise PredictionHashError(f"{sha_path} does not contain a SHA-256 hex digest")
    return m.group(1).lower()


def verify(md_path: Path, sha_path: Path) -> str:
    if not md_path.is_file():
        raise PredictionHashError(f"{md_path} is not in the repository folder yet")
    if not sha_path.is_file():
        raise PredictionHashError(f"{sha_path} is missing")
    expected = read_expected_hash(sha_path)
    actual = hashlib.sha256(md_path.read_bytes()).hexdigest()
    if actual != expected:
        raise PredictionHashError(f"{md_path.name} does not match {sha_path.name}: expected {expected}, got {actual}. "
                                  "Refusing to score.")
    return actual


def _rows(text: str) -> list[list[str]]:
    rows = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("|") and s.endswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{3,}:?", c) for c in cells if c):
                continue
            rows.append(cells)
    return rows


def parse(text: str) -> Predictions:
    pred = Predictions()
    rows = _rows(text)
    header: list[str] | None = None
    mode = None
    for cells in rows:
        if cells and cells[0] == "Defense" and "A1" in cells:
            header, mode = cells, "attack"
            continue
        if cells and cells[0] == "Item" and len(cells) >= 2 and cells[1] == "Prediction":
            header, mode = cells, "poison"
            continue
        if header is None:
            continue
        if mode == "attack" and cells[0] in ATTACK_ROWS:
            for col, value in zip(header[1:], cells[1:], strict=False):
                v = value.strip().lower()
                if v == "todo":
                    pred.todo.append(f"{cells[0]}/{col}")
                    continue
                allowed = ALLOWED_ATTACK if col in ATTACK_COLS else ALLOWED_BENIGN if col == BENIGN_COL \
                    else ALLOWED_REFUSAL if col == REFUSAL_COL else None
                if allowed is None:
                    continue
                if v not in allowed:
                    pred.problems.append(f"{cells[0]}/{col}: {value!r} is not one of {sorted(allowed)}")
                    continue
                pred.attack[(cells[0], col)] = v
        elif mode == "poison" and cells[0] in POISON_ITEMS:
            v = cells[1].strip().lower() if len(cells) > 1 else ""
            if v == "todo":
                pred.todo.append(cells[0])
                continue
            allowed = ALLOWED_DRIVER if cells[0] == "Count or share" else \
                ALLOWED_BENIGN if cells[0].startswith("Clean accuracy") else ALLOWED_COUNT
            if v not in allowed:
                pred.problems.append(f"{cells[0]}: {cells[1]!r} is not one of {sorted(allowed)}")
                continue
            pred.poisoning[cells[0]] = v
    if not pred.attack and not pred.poisoning and not pred.todo:
        raise PredictionParseError("no predictions table found")
    return pred


def load_verified(md_path: Path, sha_path: Path) -> Predictions:
    verify(md_path, sha_path)
    return parse(md_path.read_text(encoding="utf-8"))
