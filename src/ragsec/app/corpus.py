"""Rendered corpus documents (data/corpus/). The ONLY corpus files the app reads."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from ragsec import frontmatter
from ragsec.settings import TIER_ROLES, TIERS

DOC_FIELDS = ("doc_id", "title", "tier", "allowed_roles", "provenance", "updated")
PROVENANCES = ("hr_portal", "it_wiki", "admin_vault", "company_wiki", "vendor_import", "shared_drive")


@dataclass(frozen=True)
class Document:
    doc_id: str
    title: str
    tier: str
    allowed_roles: tuple[str, ...]
    provenance: str
    updated: str
    text: str
    sha256: str

    @classmethod
    def from_fields(cls, *, doc_id: str, title: str, tier: str, provenance: str, updated: str,
                    text: str, allowed_roles: list[str] | None = None) -> Document:
        if tier not in TIERS:
            raise ValueError(f"unknown tier {tier!r}")
        roles = tuple(allowed_roles) if allowed_roles is not None else tuple(TIER_ROLES[tier])
        digest = hashlib.sha256("\n".join([doc_id, title, tier, provenance, updated, text]).encode()).hexdigest()
        return cls(doc_id, title, tier, roles, provenance, updated, text, digest)


def parse_document(raw: str) -> Document:
    meta, body = frontmatter.split(raw)
    missing = [f for f in DOC_FIELDS if f not in meta]
    if missing:
        raise ValueError(f"front matter is missing {missing}")
    roles = meta["allowed_roles"]
    if not isinstance(roles, list):
        raise ValueError("allowed_roles must be a list")
    return Document.from_fields(
        doc_id=str(meta["doc_id"]),
        title=str(meta["title"]),
        tier=str(meta["tier"]),
        provenance=str(meta["provenance"]),
        updated=str(meta["updated"]),
        text=body.strip() + "\n",
        allowed_roles=[str(r) for r in roles],
    )


def load_corpus(corpus_dir: Path) -> list[Document]:
    docs: list[Document] = []
    for path in sorted(corpus_dir.glob("*/*.md")):
        docs.append(parse_document(path.read_text(encoding="utf-8")))
    ids = [d.doc_id for d in docs]
    dupes = {i for i in ids if ids.count(i) > 1}
    if dupes:
        raise ValueError(f"duplicate doc_ids in corpus: {sorted(dupes)}")
    return docs


def corpus_manifest(docs: list[Document]) -> dict[str, str]:
    """doc_id -> content hash, used by the clean-start check."""
    return {d.doc_id: d.sha256 for d in docs}
