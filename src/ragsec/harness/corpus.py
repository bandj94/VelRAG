"""``ragsec corpus render`` and the template lint (spec §5.3, §14).

Templates in data/corpus_src/{general,hr,it_admin}/ use ``{{fact:<key>}}`` and
``{{canary:<id>}}`` placeholders. Rendering writes data/corpus/{tier}/<doc_id>.md,
the only corpus files the app reads.

Lint: templates contain no hardcoded amounts, durations, or counts outside
placeholders. The allowlist below is recorded in DECISIONS.md.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from ragsec import frontmatter
from ragsec.harness import paths as hp
from ragsec.harness.data import Canary, Fact, load_canaries, load_facts
from ragsec.textnorm import normalize_newlines

PLACEHOLDER = re.compile(r"\{\{\s*(fact|canary)\s*:\s*([A-Za-z0-9_.\-]+)\s*\}\}")
LEFTOVER = re.compile(r"\{\{|\}\}")

# --- Lint allowlist (recorded in DECISIONS.md) --------------------------------
LINT_ALLOWED_PATTERNS: tuple[str, ...] = (
    r"\b20(2[5-7])\b",          # calendar years 2025-2027 in titles and headings
    r"^\s*\d+\.\s",             # ordered-list numbering at the start of a line
)
NUMBER_WORDS = (
    "one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|"
    "sixteen|seventeen|eighteen|nineteen|twenty|thirty|forty|fifty|sixty|seventy|eighty|ninety|"
    "hundred|thousand|dozen|half"
)
UNIT_WORDS = (
    "seconds?|minutes?|hours?|days?|weeks?|months?|years?|business|working|calendar|percent|"
    "dollars?|characters?|attempts?|devices?|times|approvers?|codes?|passwords?|holidays?|gb|mb|tb"
)
NUMBER_WORD_UNIT = re.compile(rf"\b({NUMBER_WORDS})(?:[\s-]+\w+)?[\s-]+({UNIT_WORDS})\b", re.IGNORECASE)


@dataclass
class LintIssue:
    doc: str
    line: int
    text: str
    reason: str


def lint_body(name: str, body: str) -> list[LintIssue]:
    issues: list[LintIssue] = []
    for n, line in enumerate(normalize_newlines(body).split("\n"), start=1):
        stripped = PLACEHOLDER.sub(" ", line)
        for pat in LINT_ALLOWED_PATTERNS:
            stripped = re.sub(pat, " ", stripped, flags=re.MULTILINE)
        if re.search(r"\d", stripped):
            issues.append(LintIssue(name, n, line.strip(), "digit outside a placeholder"))
        m = NUMBER_WORD_UNIT.search(stripped)
        if m:
            issues.append(LintIssue(name, n, line.strip(), f"number word with a unit: {m.group(0)!r}"))
    return issues


def render_text(body: str, facts: dict[str, Fact], canaries: dict[str, Canary], name: str) -> str:
    def sub(m: re.Match[str]) -> str:
        kind, key = m.group(1), m.group(2)
        if kind == "fact":
            if key not in facts:
                raise KeyError(f"{name}: unknown fact {key!r}")
            return facts[key].value
        if key not in canaries:
            raise KeyError(f"{name}: unknown canary {key!r}")
        return canaries[key].canonical

    out = PLACEHOLDER.sub(sub, body)
    if LEFTOVER.search(out):
        raise ValueError(f"{name}: unresolved placeholder syntax remains after rendering")
    return out


def template_paths(root: Path | None = None) -> list[Path]:
    return sorted(hp.corpus_src(root).glob("*/*.md"))


def render_all(root: Path | None = None, *, write: bool = True) -> dict[str, str]:
    """Render every template. Returns {relative output path: rendered text}."""
    facts = load_facts(hp.facts(root))
    canaries = {c.id: c for c in load_canaries(hp.canaries(root))}
    out_dir = hp.corpus_out(root)
    rendered: dict[str, str] = {}
    for src in template_paths(root):
        meta, body = frontmatter.split(src.read_text(encoding="utf-8"))
        tier_dir = src.parent.name
        if meta.get("tier") != tier_dir:
            raise ValueError(f"{src.name}: tier {meta.get('tier')!r} does not match folder {tier_dir!r}")
        if meta.get("doc_id") != src.stem:
            raise ValueError(f"{src.name}: doc_id {meta.get('doc_id')!r} does not match the file name")
        text = frontmatter.join(meta, render_text(body, facts, canaries, src.name))
        rel = f"{tier_dir}/{meta['doc_id']}.md"
        rendered[rel] = text
    if write:
        for old in out_dir.glob("*/*.md"):
            if f"{old.parent.name}/{old.name}" not in rendered:
                old.unlink()
        for rel, text in rendered.items():
            target = out_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", newline="\n")
    return rendered


def lint_all(root: Path | None = None) -> list[LintIssue]:
    issues: list[LintIssue] = []
    for src in template_paths(root):
        _meta, body = frontmatter.split(src.read_text(encoding="utf-8"))
        issues.extend(lint_body(src.name, body))
    return issues


def word_count(text: str) -> int:
    return len(re.findall(r"[A-Za-z0-9][A-Za-z0-9'’.-]*", text))
