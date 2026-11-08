"""Corpus tests (spec §14)."""

from __future__ import annotations

import re

from helpers import ROOT, corpus_docs

from ragsec import frontmatter
from ragsec.app import prompts
from ragsec.app.corpus import PROVENANCES
from ragsec.harness import checks, corpus
from ragsec.harness.data import load_canaries, load_corpus_labels, load_facts, routing_code
from ragsec.settings import TIER_ROLES, load_app_config

DOC_ID = re.compile(r"^(gen|hr|adm)-[a-z0-9]+(?:-[a-z0-9]+)*$")
PREFIX = {"general": "gen", "hr": "hr", "it_admin": "adm"}


def test_forty_documents_with_valid_front_matter() -> None:
    docs = corpus_docs()
    assert len(docs) == 40
    tiers = [d.tier for d in docs]
    assert (tiers.count("general"), tiers.count("hr"), tiers.count("it_admin")) == (28, 6, 6)
    for d in docs:
        assert DOC_ID.fullmatch(d.doc_id), d.doc_id
        assert d.doc_id.startswith(PREFIX[d.tier] + "-")
        assert list(d.allowed_roles) == TIER_ROLES[d.tier]
        assert d.provenance in PROVENANCES
        assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", d.updated)
        assert 300 <= corpus.word_count(d.text) <= 900, (d.doc_id, corpus.word_count(d.text))


def test_provenance_mix_never_identifies_poison() -> None:
    general = [d for d in corpus_docs() if d.tier == "general"]
    labels = load_corpus_labels()
    imported = {d.doc_id for d in general if d.provenance == "vendor_import"}
    shared = {d.doc_id for d in general if d.provenance == "shared_drive"}
    assert len(imported) >= 3 and len(shared) >= 3
    outside = imported | shared
    assert set(labels["external_link_docs"]) <= outside
    assert set(labels["hard_negatives"]) & outside
    assert 3 <= len(labels["hard_negatives"]) <= 4
    assert len(labels["external_link_docs"]) == 2


def test_templates_render_with_every_placeholder_resolved() -> None:
    rendered = corpus.render_all(write=False)
    assert len(rendered) == 40
    for rel, text in rendered.items():
        assert "{{" not in text and "}}" not in text, rel
        committed = (ROOT / "data" / "corpus" / rel).read_text(encoding="utf-8")
        assert committed == text, f"{rel} is stale: run `ragsec corpus render`"


def test_templates_have_no_hardcoded_numbers() -> None:
    assert corpus.lint_all() == []


def test_lint_catches_hardcoded_values() -> None:
    issues = corpus.lint_body("x.md", "You get 15 days of PTO.\nRetry after two minutes.\n1. A numbered step\n")
    reasons = [i.reason for i in issues]
    assert any("digit" in r for r in reasons)
    assert any("number word" in r for r in reasons)
    assert all(i.line != 3 for i in issues)


def test_every_canary_appears_only_in_its_own_tier() -> None:
    docs = corpus_docs()
    for c in load_canaries():
        if c.tier == "system":
            continue
        for d in docs:
            hit = checks.canary_hits(d.text, [c])
            if hit:
                assert d.tier == c.tier, (c.id, d.doc_id)
        home = next(d for d in docs if d.doc_id == c.doc_id)
        assert c.canonical in home.text, (c.id, c.doc_id)


def test_routing_code_appears_only_in_the_system_prompt() -> None:
    cfg = load_app_config()
    code = routing_code(load_canaries())
    assert code == cfg.prompt.routing_code
    for d in corpus_docs():
        assert not checks.canary_hits(d.text, [c for c in load_canaries() if c.tier == "system"]), d.doc_id
    msg = prompts.build_system_message(cfg, user_email="a@velmora.example", role="employee", d4=False, marker=None)
    assert code in msg.text


def _ngrams(text: str, n: int = 8) -> set[tuple[str, ...]]:
    words = re.findall(r"[a-z0-9]+", text.lower())
    return {tuple(words[i : i + n]) for i in range(len(words) - n + 1)}


def test_no_document_shares_an_8_word_span_with_fixed_instruction_text() -> None:
    cfg = load_app_config()
    for d4 in (False, True):
        fixed = _ngrams(prompts.fixed_instruction_text(cfg, d4=d4))
        assert fixed
        for d in corpus_docs():
            shared = fixed & _ngrams(d.text)
            assert not shared, (d.doc_id, d4, sorted(shared)[:2])


def test_restricted_facts_only_in_their_tier() -> None:
    facts = load_facts()
    for src in corpus.template_paths():
        meta, body = frontmatter.split(src.read_text(encoding="utf-8"))
        for kind, key in corpus.PLACEHOLDER.findall(body):
            if kind == "fact" and facts[key].tier != "general":
                assert facts[key].tier == meta["tier"], (src.name, key)
