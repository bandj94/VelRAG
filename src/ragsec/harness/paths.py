"""Harness-only paths. App code must never import this module (rule 3)."""

from __future__ import annotations

from pathlib import Path

from ragsec.paths import repo_root


def root() -> Path:
    return repo_root()


def data(r: Path | None = None) -> Path:
    return (r or root()) / "data"


def facts(r: Path | None = None) -> Path:
    return data(r) / "facts.yaml"


def canaries(r: Path | None = None) -> Path:
    return data(r) / "canaries.yaml"


def directory(r: Path | None = None) -> Path:
    return data(r) / "directory.yaml"


def corpus_src(r: Path | None = None) -> Path:
    return data(r) / "corpus_src"


def corpus_out(r: Path | None = None) -> Path:
    return data(r) / "corpus"


def corpus_labels(r: Path | None = None) -> Path:
    return data(r) / "corpus_labels.yaml"


def benign(r: Path | None = None) -> Path:
    return data(r) / "benign" / "benign.yaml"


def attacks(r: Path | None = None) -> Path:
    return (r or root()) / "attacks"


def seeds(r: Path | None = None) -> Path:
    return attacks(r) / "seeds"


def frozen(r: Path | None = None) -> Path:
    return attacks(r) / "frozen"


def adaptive(r: Path | None = None) -> Path:
    return attacks(r) / "adaptive"


def doc_ids(r: Path | None = None) -> Path:
    return attacks(r) / "doc_ids.yaml"


def freeze_md(r: Path | None = None) -> Path:
    return (r or root()) / "FREEZE.md"


def harness_config(r: Path | None = None) -> Path:
    return (r or root()) / "config" / "harness.yaml"


def results(r: Path | None = None) -> Path:
    return (r or root()) / "results"


def raw_results(r: Path | None = None) -> Path:
    return results(r) / "raw"


def summary(r: Path | None = None) -> Path:
    return results(r) / "summary"


def audit(r: Path | None = None) -> Path:
    return results(r) / "audit"


def logs(r: Path | None = None) -> Path:
    return (r or root()) / "logs"


def scratch(r: Path | None = None) -> Path:
    return (r or root()) / "scratch"


def report_md(r: Path | None = None) -> Path:
    return (r or root()) / "REPORT.md"
