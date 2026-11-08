"""Loaders for scoring data: facts, canaries, directory, benign set, attack cases."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cached_property
from pathlib import Path
from typing import Any

import yaml

from ragsec.harness import paths as hp


def read_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as fh:
        return yaml.safe_load(fh)


# --------------------------------------------------------------------------- facts
@dataclass(frozen=True)
class Fact:
    key: str
    value: str
    patterns: tuple[str, ...]
    tier: str

    @cached_property
    def compiled(self) -> tuple[re.Pattern[str], ...]:
        return tuple(re.compile(p, re.IGNORECASE) for p in self.patterns)


def load_facts(path: Path | None = None) -> dict[str, Fact]:
    raw = read_yaml(path or hp.facts())["facts"]
    return {k: Fact(k, str(v["value"]), tuple(v.get("patterns", [])), str(v.get("tier", "general")))
            for k, v in raw.items()}


# ------------------------------------------------------------------------ canaries
@dataclass(frozen=True)
class Canary:
    id: str
    tier: str
    doc_id: str | None
    kind: str
    values: tuple[str, ...]

    @property
    def canonical(self) -> str:
        return self.values[0]


def load_canaries(path: Path | None = None) -> list[Canary]:
    raw = read_yaml(path or hp.canaries())["canaries"]
    return [Canary(c["id"], c["tier"], c.get("doc_id"), c.get("kind", ""), tuple(str(v) for v in c["values"]))
            for c in raw]


def routing_code(canaries: list[Canary]) -> str:
    for c in canaries:
        if c.tier == "system":
            return c.canonical
    raise ValueError("no system-tier canary (routing code) in canaries.yaml")


# ----------------------------------------------------------------------- directory
ROLE_TIERS: dict[str, set[str]] = {
    "employee": {"general"},
    "hr": {"general", "hr"},
    "it_admin": {"general", "it_admin"},
    "external": {"general"},
}


@dataclass
class Directory:
    domain: str
    pools: dict[str, list[str]]
    people: dict[str, str]  # email (lowercase) -> role
    load_users: list[str] = field(default_factory=list)
    colleagues: list[dict[str, Any]] = field(default_factory=list)

    def role_of(self, address: str) -> str:
        """Role that decides what a recipient may see (§8.2)."""
        a = address.strip().lower().rstrip(".")
        if a in self.people:
            return self.people[a]
        domain = a.rsplit("@", 1)[-1] if "@" in a else ""
        return "employee" if domain == self.domain else "external"

    def tiers_visible(self, address: str) -> set[str]:
        return ROLE_TIERS[self.role_of(address)]


def load_directory(path: Path | None = None) -> Directory:
    raw = read_yaml(path or hp.directory())
    pools = {role: [e.lower() for e in emails] for role, emails in raw["pools"].items()}
    people: dict[str, str] = {}
    for role, emails in pools.items():
        for e in emails:
            people[e] = role
    for c in raw.get("colleagues", []):
        people[c["email"].lower()] = c["role"]
    load = [e.lower() for e in raw.get("load_users", {}).get("emails", [])]
    for e in load:
        people[e] = raw.get("load_users", {}).get("role", "employee")
    return Directory(raw["domain"], pools, people, load, raw.get("colleagues", []))


# -------------------------------------------------------------------- corpus labels
def load_corpus_labels(path: Path | None = None) -> dict[str, list[str]]:
    raw = read_yaml(path or hp.corpus_labels()) or {}
    return {k: list(v) for k, v in raw.items()}


# --------------------------------------------------------------------- case files
def load_case_file(path: Path) -> list[dict[str, Any]]:
    raw = read_yaml(path)
    if raw is None:
        return []
    if isinstance(raw, dict) and "cases" in raw:
        raw = raw["cases"]
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a list of cases")
    return raw


def load_benign(path: Path | None = None) -> list[dict[str, Any]]:
    return load_case_file(path or hp.benign())
