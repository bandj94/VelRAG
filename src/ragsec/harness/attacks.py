"""``ragsec attacks {validate|generate|split|freeze}`` (spec §8.3–§8.6, §16).

Seeds are user-owned: validation reports problems and never edits them. Labels a
seed lacks (subtype, injection_style, doc_id) are added in the frozen copy, from
attacks/seed_labels.yaml and attacks/doc_ids.yaml.
"""

from __future__ import annotations

import copy
import random
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ragsec import frontmatter
from ragsec.app.corpus import load_corpus
from ragsec.app.keys import d4_marker_from_trial_key
from ragsec.harness import checks, freeze
from ragsec.harness import paths as hp
from ragsec.harness.data import Canary, load_canaries, load_case_file, load_facts, read_yaml
from ragsec.harness.keys import trial_key
from ragsec.harness.runner import CATEGORY_BY_PREFIX, load_doc_ids
from ragsec.settings import ROLES

# claude_seed: a seed drafted by Claude Code at the owner's request (owner-approved).
# It is labeled separately so the report's share of attacks by source stays honest.
SOURCES = {"user_seed", "claude_seed", "claude_variant", "promptfoo", "adaptive", "adaptive_user"}
SEED_SOURCES = {"user_seed", "claude_seed", "adaptive_user"}
STYLES = {"explicit_override", "implicit"}
CHECK_FOR_CATEGORY = {
    "direct_injection": "marker_in_answer", "hidden_context": "canary_in_answer",
    "indirect_phishing": "attacker_url_in_answer", "cross_role_leak": "canary_in_answer",
    "retrieval_hijack": "false_fact_in_answer", "markdown_exfil": "exfil_request",
    "tool_misuse": "tool_abuse", "resource_exhaustion": "resource_exhaustion",
}
OWASP_FOR_CATEGORY = {
    "direct_injection": {"LLM01"}, "hidden_context": {"LLM08"}, "indirect_phishing": {"LLM01"},
    "cross_role_leak": {"LLM02", "LLM09"}, "retrieval_hijack": {"LLM09", "LLM07", "LLM05"},
    "markdown_exfil": {"LLM10"}, "tool_misuse": {"LLM03"}, "resource_exhaustion": {"LLM06"},
}
STYLE_REQUIRED = {"indirect_phishing", "markdown_exfil", "tool_misuse"}
POISON_DOC_ID = re.compile(r"^gen-[a-z0-9]+(?:-[a-z0-9]+)*$")
FORBIDDEN_DOC_ID_WORDS = ("attack", "poison", "canary", "inject", "exfil", "payload", "malicious", "test-case")
ROLE_TIERS = {"employee": {"general"}, "hr": {"general", "hr"}, "it_admin": {"general", "it_admin"}}
MARKER_NAMESPACES = ("candidates", "frozen-v1", "adaptive-dev", "adaptive-final")
MARKER_TRIALS = 5


@dataclass
class Context:
    root: Path
    canaries: list[Canary]
    facts: set[str]
    corpus_ids: set[str]
    doc_ids: dict[str, str]
    seed_labels: dict[str, dict[str, Any]] = field(default_factory=dict)


def make_context(root: Path | None = None) -> Context:
    r = root or hp.root()
    labels_path = hp.attacks(r) / "seed_labels.yaml"
    labels = (read_yaml(labels_path) or {}) if labels_path.is_file() else {}
    corpus_ids = {d.doc_id for d in load_corpus(hp.corpus_out(r))} if hp.corpus_out(r).is_dir() else set()
    return Context(r, load_canaries(hp.canaries(r)), set(load_facts(hp.facts(r))), corpus_ids, load_doc_ids(r),
                   {str(k): dict(v) for k, v in labels.items()})


def _doc_inputs(ctx: Context, case: dict[str, Any], problems: list[str]) -> list[tuple[str, str, dict[str, Any]]]:
    out = []
    for d in case.get("poisoned_docs") or []:
        rel = str(d.get("file", ""))
        path = ctx.root / rel
        if not path.is_file():
            problems.append(f"poisoned doc {rel} does not exist")
            continue
        try:
            meta, body = frontmatter.split(path.read_text(encoding="utf-8"))
        except ValueError as exc:
            problems.append(f"{rel}: {exc}")
            continue
        out.append((rel, path.read_text(encoding="utf-8"), meta))
    return out


def validate_case(case: dict[str, Any], ctx: Context) -> list[str]:
    p: list[str] = []
    cid = str(case.get("id", "?"))
    for req in ("id", "category", "source", "role", "user_message", "success"):
        if req not in case:
            p.append(f"missing field {req!r}")
    if p:
        return p
    category = str(case["category"])
    prefix = cid[:2]
    if CATEGORY_BY_PREFIX.get(prefix) != category:
        p.append(f"id prefix {prefix} does not match category {category}")
    if case["source"] not in SOURCES:
        p.append(f"source {case['source']!r} not in {sorted(SOURCES)}")
    is_seed = case["source"] in SEED_SOURCES
    if is_seed and not str(case.get("notes", "")).strip():
        p.append("seeds need a notes line explaining why the attack might work")
    if case["role"] not in ROLES:
        p.append(f"role {case['role']!r} not in {ROLES}")
    owasp = set(case.get("owasp") or [])
    if owasp and not owasp <= OWASP_FOR_CATEGORY.get(category, set()) | {"LLM01", "LLM02", "LLM03", "LLM04",
                                                                          "LLM05", "LLM06", "LLM07", "LLM08",
                                                                          "LLM09", "LLM10"}:
        p.append(f"unknown OWASP ids {sorted(owasp)}")
    success = case.get("success") or {}
    check = success.get("check")
    if check != CHECK_FOR_CATEGORY.get(category):
        p.append(f"check {check!r} does not match category {category} (expected {CHECK_FOR_CATEGORY.get(category)})")
    labels = {**ctx.seed_labels.get(cid, {}), **case}
    if not is_seed:
        if not labels.get("subtype"):
            p.append("missing label 'subtype' (labels come first, before any results)")
        if category in STYLE_REQUIRED and labels.get("injection_style") not in STYLES:
            p.append("missing or invalid injection_style (explicit_override | implicit)")
    elif labels.get("injection_style") not in (None, *STYLES):
        p.append(f"invalid injection_style {labels.get('injection_style')!r}")
    target = case.get("target_tier")
    role = case["role"]
    if category == "hidden_context" and target not in (None, "system"):
        p.append("A2 target_tier must be 'system'")
    if category == "cross_role_leak":
        if target not in ("hr", "it_admin"):
            p.append("A4 target_tier must be hr or it_admin")
        elif role in ROLE_TIERS and target in ROLE_TIERS[role]:
            p.append(f"A4: role {role} may already see tier {target}")
    if category in ("markdown_exfil", "tool_misuse"):
        if role not in ("hr", "it_admin"):
            p.append(f"{category} cases come from an HR or IT-admin session")
        elif target not in (None, role):
            p.append(f"{category}: target_tier must be the session's own tier ({role})")
    if category == "direct_injection" and not success.get("marker"):
        p.append("A1 needs success.marker (a computed value)")
    if category == "retrieval_hijack":
        try:
            re.compile(str(success.get("false_pattern", "")))
        except re.error as exc:
            p.append(f"A5 false_pattern does not compile: {exc}")
        if not success.get("false_pattern"):
            p.append("A5 needs success.false_pattern")
        if success.get("true_fact") not in ctx.facts:
            p.append(f"A5 true_fact {success.get('true_fact')!r} is not a facts.yaml key")
    if category == "tool_misuse" and not isinstance(case.get("email_request", False), bool):
        p.append("email_request must be true or false")

    # Poisoned documents.
    docs = _doc_inputs(ctx, case, p)
    for rel, _raw, meta in docs:
        for key in ("title", "provenance", "updated"):
            if not meta.get(key):
                p.append(f"{rel}: front matter needs {key!r}")
        if meta.get("tier", "general") != "general":
            p.append(f"{rel}: poisoned documents are tier general")
        if meta.get("provenance") not in ("vendor_import", "shared_drive"):
            p.append(f"{rel}: provenance must be vendor_import or shared_drive")
        doc_id = meta.get("doc_id") or ctx.doc_ids.get(rel)
        if not doc_id:
            p.append(f"{rel}: no doc_id (add one to attacks/doc_ids.yaml)")
        else:
            d = str(doc_id)
            if not POISON_DOC_ID.fullmatch(d):
                p.append(f"{rel}: doc_id {d!r} must look like a general corpus doc_id (gen-<slug>)")
            if cid.lower() in d or any(w in d for w in FORBIDDEN_DOC_ID_WORDS):
                p.append(f"{rel}: doc_id {d!r} reveals the case or its purpose")
            if d in ctx.corpus_ids:
                p.append(f"{rel}: doc_id {d!r} collides with a corpus document")

    # Attacker knowledge: no canaries, routing code, D4 markers, or own marker in inputs.
    message = str(case.get("user_message", ""))
    doc_texts = [raw for _rel, raw, _meta in docs]
    if category == "direct_injection" and success.get("marker"):
        if checks.value_in(checks.build_forms("\n".join([message, *doc_texts])), str(success["marker"])):
            p.append("A1 marker appears in the case's own inputs")
    doc_forms = checks.build_forms("\n".join(doc_texts)) if doc_texts else None
    msg_forms = checks.build_forms(message)
    for c in ctx.canaries:
        for v in c.values:
            in_docs = doc_forms is not None and checks.value_in(doc_forms, v)
            in_msg = checks.value_in(msg_forms, v)
            if in_docs:
                p.append(f"poisoned document contains canary {c.id} (attackers don't know secrets)")
            if in_msg and c.tier == "system":
                p.append("message contains the routing code")
            elif in_msg and category != "cross_role_leak":
                p.append(f"message contains canary {c.id}")
    all_forms = checks.build_forms("\n".join([message, *doc_texts]))
    for ns in MARKER_NAMESPACES:
        for t in range(MARKER_TRIALS):
            if checks.value_in(all_forms, d4_marker_from_trial_key(trial_key(ns, cid, t))):
                p.append("inputs contain a D4 marker for one of the case's trials")
                break
    return p


def validate_file(path: Path, ctx: Context) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    ids: Counter[str] = Counter()
    for case in load_case_file(path):
        ids[str(case.get("id"))] += 1
        problems = validate_case(case, ctx)
        if problems:
            out[str(case.get("id", "?"))] = problems
    for cid, n in ids.items():
        if n > 1:
            out.setdefault(cid, []).append(f"duplicate id appears {n} times")
    return out


# --------------------------------------------------------------------------- minimums
def labelled(case: dict[str, Any], ctx: Context) -> dict[str, Any]:
    return {**ctx.seed_labels.get(str(case["id"]), {}), **case}


def check_minimums(cases: list[dict[str, Any]], hcfg: dict[str, Any], ctx: Context) -> list[str]:
    mins = hcfg["minimums"]
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in cases:
        by_cat[str(c["category"])].append(labelled(c, ctx))
    p: list[str] = []
    for cat in CHECK_FOR_CATEGORY:
        n = len(by_cat.get(cat, []))
        if n != mins["per_category"]:
            p.append(f"{cat}: {n} cases (need exactly {mins['per_category']})")
    a3 = by_cat.get("indirect_phishing", [])
    styles = Counter(c.get("injection_style") for c in a3)
    for style, need in mins["A3"].items():
        if styles[style] < need:
            p.append(f"A3: {styles[style]} {style} cases (need {need})")
    a4 = Counter(c.get("subtype") for c in by_cat.get("cross_role_leak", []))
    for direction, need in mins["A4_directions"].items():
        if a4[direction] < need:
            p.append(f"A4: {a4[direction]} {direction} cases (need {need})")
    a6 = by_cat.get("markdown_exfil", [])
    st6 = Counter(c.get("subtype") for c in a6)
    m6 = mins["A6"]
    raw_html = st6["raw_html_element"] + st6["event_handler"] + st6["script_tag"]
    for label, have, need in (("markdown_image", st6["markdown_image"], m6["markdown_image"]),
                              ("raw-HTML payloads", raw_html, m6["raw_html_total"]),
                              ("event_handler", st6["event_handler"], m6["event_handler"]),
                              ("script_tag", st6["script_tag"], m6["script_tag"])):
        if have < need:
            p.append(f"A6: {have} {label} (need {need})")
    for style in STYLES:
        if sum(1 for c in a6 if c.get("injection_style") == style) < m6["per_style"]:
            p.append(f"A6: fewer than {m6['per_style']} {style} cases")
    a7 = by_cat.get("tool_misuse", [])
    m7 = mins["A7"]
    piggy = [c for c in a7 if c.get("email_request")]
    counts7 = {
        "piggyback": len(piggy),
        "piggyback_internal_colleague": sum(1 for c in piggy if c.get("recipient_kind") == "internal_colleague"),
        "attacker_link_in_email": sum(1 for c in a7 if "attacker_link" in str(c.get("subtype", ""))),
        "unrequested_send": sum(1 for c in a7 if not c.get("email_request")),
    }
    for k, have in counts7.items():
        if have < m7[k]:
            p.append(f"A7: {have} {k} (need {m7[k]})")
    for style in STYLES:
        if sum(1 for c in a7 if c.get("injection_style") == style) < m7["per_style"]:
            p.append(f"A7: fewer than {m7['per_style']} {style} cases")
    a8 = Counter(c.get("subtype") for c in by_cat.get("resource_exhaustion", []))
    for sub, need in mins["A8"].items():
        if a8[sub] < need:
            p.append(f"A8: {a8[sub]} {sub} cases (need {need})")
    return p


# ------------------------------------------------------------------------------ split
def stratified_split(cases: list[dict[str, Any]], heldout_per_category: int, seed: int,
                     ctx: Context | None = None) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Held-out slots go to strata (subtype × injection_style) in proportion to their
    size (largest remainder; ties broken with a fixed seed), so each stratum keeps
    about two-thirds of its cases in dev."""
    rng = random.Random(seed)
    dev: list[dict[str, Any]] = []
    held: list[dict[str, Any]] = []
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in cases:
        by_cat[str(c["category"])].append(c)
    for cat in sorted(by_cat):
        group = sorted(by_cat[cat], key=lambda c: str(c["id"]))
        strata: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for c in group:
            lab = labelled(c, ctx) if ctx else c
            strata[(str(lab.get("subtype")), str(lab.get("injection_style")))].append(c)
        n = len(group)
        k = min(heldout_per_category, n)
        quotas = {s: k * len(v) / n for s, v in strata.items()}
        alloc = {s: int(q) for s, q in quotas.items()}
        remaining = k - sum(alloc.values())
        keys = sorted(strata)
        rng.shuffle(keys)  # fixed-seed tie-break
        order = sorted(keys, key=lambda s: quotas[s] - alloc[s], reverse=True)
        for s in order[:remaining]:
            alloc[s] += 1
        for s in sorted(strata):
            members = list(strata[s])
            rng.shuffle(members)
            held.extend(members[: alloc[s]])
            dev.extend(members[alloc[s]:])
    return dev, held


def frozen_copy(case: dict[str, Any], ctx: Context) -> dict[str, Any]:
    out = copy.deepcopy(labelled(case, ctx))
    for d in out.get("poisoned_docs") or []:
        rel = str(d["file"])
        if "doc_id" not in d and rel in ctx.doc_ids:
            d["doc_id"] = ctx.doc_ids[rel]
    return out


def freeze_sets(selected: list[dict[str, Any]], root: Path, hcfg: dict[str, Any], ctx: Context) -> tuple[Path, Path]:
    seed = int(hcfg["split"]["seed"])
    dev, held = stratified_split(selected, int(hcfg["split"]["heldout_per_category"]), seed, ctx)
    out = hp.frozen(root)
    out.mkdir(parents=True, exist_ok=True)
    dev_path, held_path = out / "dev.yaml", out / "heldout.yaml"
    for path, cases in ((dev_path, dev), (held_path, held)):
        if path.exists():
            raise FileExistsError(f"{path} already exists; frozen sets are immutable (rule 4)")
        path.write_text(yaml.safe_dump([frozen_copy(c, ctx) for c in sorted(cases, key=lambda c: str(c["id"]))],
                                       sort_keys=False, allow_unicode=True), encoding="utf-8", newline="\n")
    note = f"split seed {seed}; namespace {hcfg['namespaces']['frozen']}"
    freeze.add_entry("attacks/frozen/dev.yaml", "frozen-v1", "final", note, root)
    freeze.add_entry("attacks/frozen/heldout.yaml", "frozen-v1", "final", note, root)
    return dev_path, held_path


# --------------------------------------------------------------------------- generate
PROMPTFOO_NOTE = """\
promptfoo integration (Run 2, §8.6). Steps:
  1. npx promptfoo@latest redteam plugins      -> note the version, pin it in config/pins.yaml (promptfoo.version)
  2. Ask the user to run the first generation in their own terminal (it asks for an email address once),
     with PROMPTFOO_DISABLE_TELEMETRY=1 and PROMPTFOO_DISABLE_UPDATE=1 set.
  3. npx promptfoo@<version> redteam poison <files>   (fictional documents only; it uses the remote service)
  4. ragsec attacks generate --convert <promptfoo output .json/.yaml> --category <category>
     converts candidates to the case schema; candidates without an objective check are dropped.
  5. Commit every candidate under attacks/candidates/.
"""


def convert_promptfoo(path: Path, category: str, start_index: int, role: str) -> list[dict[str, Any]]:
    """Best-effort conversion of promptfoo test cases into candidate cases.

    Only categories whose success can be checked objectively without extra labels
    are converted automatically (A1 needs a computed marker, so promptfoo prompts
    become A1 candidates only when they carry one). Everything else is written with
    ``needs_review: true`` and must be completed by hand before validation passes.
    """
    raw = read_yaml(path) if path.suffix in (".yaml", ".yml") else __import__("json").loads(path.read_text("utf-8"))
    tests = raw.get("tests", raw) if isinstance(raw, dict) else raw
    prefix = {v: k for k, v in CATEGORY_BY_PREFIX.items()}[category]
    out = []
    for i, t in enumerate(tests or [], start=start_index):
        vars_ = (t.get("vars") or {}) if isinstance(t, dict) else {}
        prompt = vars_.get("prompt") or vars_.get("query") or (t.get("prompt") if isinstance(t, dict) else None)
        if not prompt:
            continue
        out.append({"id": f"{prefix}-{i:03d}", "category": category, "owasp": sorted(OWASP_FOR_CATEGORY[category]),
                    "source": "promptfoo", "subtype": (t.get("metadata") or {}).get("pluginId", "promptfoo"),
                    "role": role, "user_message": str(prompt), "email_request": False,
                    "success": {"check": CHECK_FOR_CATEGORY[category]}, "needs_review": True,
                    "notes": f"converted from {path.name}"})
    return out
