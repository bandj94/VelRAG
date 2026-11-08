"""FREEZE.md: hashes of every frozen file, seeds, namespaces, dates (rule 4).

The harness checks hashes from FREEZE.md and refuses to run on a mismatch. The
machine-readable part is the table between the FREEZE:TABLE markers.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from ragsec.harness import paths as hp

BEGIN = "<!-- FREEZE:TABLE:BEGIN -->"
END = "<!-- FREEZE:TABLE:END -->"
HEADER = "| File | Version | SHA-256 | Status | Date | Notes |\n|---|---|---|---|---|---|"


class FreezeError(RuntimeError):
    pass


@dataclass(frozen=True)
class FreezeEntry:
    file: str
    version: str
    sha256: str
    status: str  # draft | final | superseded
    date: str
    notes: str


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_entries(freeze_md: Path | None = None) -> list[FreezeEntry]:
    path = freeze_md or hp.freeze_md()
    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8")
    if BEGIN not in text or END not in text:
        return []
    block = text.split(BEGIN, 1)[1].split(END, 1)[0]
    out: list[FreezeEntry] = []
    for line in block.splitlines():
        line = line.strip()
        if not line.startswith("|") or line.startswith("|---") or line.startswith("| File"):
            continue
        cells = [c.strip().strip("`") for c in line.strip("|").split("|")]
        if len(cells) < 6:
            continue
        out.append(FreezeEntry(*cells[:6]))
    return out


def current_entry(rel_file: str, freeze_md: Path | None = None) -> FreezeEntry | None:
    entries = [e for e in read_entries(freeze_md) if e.file == rel_file and e.status != "superseded"]
    return entries[-1] if entries else None


def verify(rel_file: str, root: Path | None = None, freeze_md: Path | None = None) -> FreezeEntry:
    """Return the active entry if the file matches its frozen hash; raise otherwise."""
    r = root or hp.root()
    entry = current_entry(rel_file, freeze_md or hp.freeze_md(r))
    if entry is None:
        raise FreezeError(f"{rel_file} is not frozen in FREEZE.md; freeze it before running it")
    actual = sha256_file(r / rel_file)
    if actual.lower() != entry.sha256.lower():
        raise FreezeError(f"{rel_file} does not match its frozen hash ({entry.version}): "
                          f"expected {entry.sha256}, got {actual}. Frozen files are immutable (rule 4).")
    return entry


def add_entry(rel_file: str, version: str, status: str, notes: str = "",
              root: Path | None = None, supersede_previous: bool = False) -> FreezeEntry:
    r = root or hp.root()
    path = hp.freeze_md(r)
    text = path.read_text(encoding="utf-8") if path.is_file() else ""
    if BEGIN not in text:
        text = text.rstrip() + f"\n\n{BEGIN}\n{HEADER}\n{END}\n"
    head, rest = text.split(BEGIN, 1)
    block, tail = rest.split(END, 1)
    lines = [ln for ln in block.strip().splitlines() if ln.strip()]
    if supersede_previous:
        new_lines = []
        for ln in lines:
            cells = [c.strip() for c in ln.strip().strip("|").split("|")]
            if len(cells) >= 6 and cells[0].strip("`") == rel_file and cells[3] != "superseded":
                cells[3] = "superseded"
                ln = "| " + " | ".join(cells) + " |"
            new_lines.append(ln)
        lines = new_lines
    entry = FreezeEntry(rel_file, version, sha256_file(r / rel_file), status,
                        _dt.date.today().isoformat(), notes.replace("|", "/"))
    if not lines or not lines[0].startswith("| File"):
        lines = HEADER.splitlines() + lines
    lines.append(f"| `{entry.file}` | {entry.version} | {entry.sha256} | {entry.status} | {entry.date} | {entry.notes} |")
    path.write_text(head + BEGIN + "\n" + "\n".join(lines) + "\n" + END + tail, encoding="utf-8", newline="\n")
    return entry


def set_status(rel_file: str, status: str, root: Path | None = None) -> None:
    r = root or hp.root()
    path = hp.freeze_md(r)
    text = path.read_text(encoding="utf-8")
    head, rest = text.split(BEGIN, 1)
    block, tail = rest.split(END, 1)
    out = []
    for ln in block.strip().splitlines():
        cells = [c.strip() for c in ln.strip().strip("|").split("|")]
        if len(cells) >= 6 and cells[0].strip("`") == rel_file and cells[3] not in ("superseded",):
            cells[3] = status
            ln = "| " + " | ".join(cells) + " |"
        out.append(ln)
    path.write_text(head + BEGIN + "\n" + "\n".join(out) + "\n" + END + tail, encoding="utf-8", newline="\n")


VERSION_RE = re.compile(r"^benign-v(\d+)$")
