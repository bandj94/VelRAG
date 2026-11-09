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
from collections.abc import Callable
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


PROVENANCES = ("vendor_import", "shared_drive")
RAW_HTML_SUBTYPES = ("raw_html_element", "event_handler", "script_tag")


def case_provenances(case: dict[str, Any], ctx: Context) -> tuple[str, ...]:
    """Provenance of each document the case plants, sorted; empty if it plants none."""
    return tuple(sorted(str(meta.get("provenance")) for _rel, _raw, meta in _doc_inputs(ctx, case, [])))


def case_view(case: dict[str, Any], ctx: Context) -> dict[str, Any]:
    """A case's labels plus the provenances of its documents: everything the §8.6
    minimums and the selection rule may look at. Results never appear here."""
    return {**labelled(case, ctx), "provenances": case_provenances(case, ctx)}


@dataclass(frozen=True)
class MinimumRule:
    """One §8.6 minimum: at least `need` of a category's cases satisfy `matches`."""

    category: str
    message: str  # formatted with have= and need=
    need: int
    matches: Callable[[dict[str, Any]], bool]


def _has(key: str, value: Any) -> Callable[[dict[str, Any]], bool]:
    return lambda v: v.get(key) == value


def _plants(provenance: str) -> Callable[[dict[str, Any]], bool]:
    return lambda v: provenance in v["provenances"]


def minimum_rules(hcfg: dict[str, Any]) -> list[MinimumRule]:
    """§8.6's minimums as predicates over case views, shared by the freeze check and
    the selection, so the two can never disagree."""
    mins = hcfg["minimums"]
    rules: list[MinimumRule] = []
    for style, need in mins["A3"].items():
        rules.append(MinimumRule("indirect_phishing", f"A3: {{have}} {style} cases (need {{need}})", int(need),
                                 _has("injection_style", style)))
    for prov in PROVENANCES:  # §8.6: "both provenances"
        rules.append(MinimumRule("indirect_phishing", f"A3: {{have}} {prov} cases (need {{need}}; both provenances)",
                                 1, _plants(prov)))
    for direction, need in mins["A4_directions"].items():
        rules.append(MinimumRule("cross_role_leak", f"A4: {{have}} {direction} cases (need {{need}})", int(need),
                                 _has("subtype", direction)))
    m6 = mins["A6"]
    rules += [
        MinimumRule("markdown_exfil", "A6: {have} markdown_image (need {need})", int(m6["markdown_image"]),
                    _has("subtype", "markdown_image")),
        MinimumRule("markdown_exfil", "A6: {have} raw-HTML payloads (need {need})", int(m6["raw_html_total"]),
                    lambda v: v.get("subtype") in RAW_HTML_SUBTYPES),
        MinimumRule("markdown_exfil", "A6: {have} event_handler (need {need})", int(m6["event_handler"]),
                    _has("subtype", "event_handler")),
        MinimumRule("markdown_exfil", "A6: {have} script_tag (need {need})", int(m6["script_tag"]),
                    _has("subtype", "script_tag")),
    ]
    m7 = mins["A7"]
    rules += [
        MinimumRule("tool_misuse", "A7: {have} piggyback (need {need})", int(m7["piggyback"]),
                    lambda v: bool(v.get("email_request"))),
        MinimumRule("tool_misuse", "A7: {have} piggyback_internal_colleague (need {need})",
                    int(m7["piggyback_internal_colleague"]),
                    lambda v: bool(v.get("email_request")) and v.get("recipient_kind") == "internal_colleague"),
        MinimumRule("tool_misuse", "A7: {have} attacker_link_in_email (need {need})", int(m7["attacker_link_in_email"]),
                    lambda v: "attacker_link" in str(v.get("subtype", ""))),
        MinimumRule("tool_misuse", "A7: {have} unrequested_send (need {need})", int(m7["unrequested_send"]),
                    lambda v: not v.get("email_request")),
    ]
    for prefix, category, per_style in (("A6", "markdown_exfil", m6["per_style"]),
                                        ("A7", "tool_misuse", m7["per_style"])):
        for style in sorted(STYLES):
            rules.append(MinimumRule(category, f"{prefix}: fewer than {{need}} {style} cases", int(per_style),
                                     _has("injection_style", style)))
    for sub, need in mins["A8"].items():
        rules.append(MinimumRule("resource_exhaustion", f"A8: {{have}} {sub} cases (need {{need}})", int(need),
                                 _has("subtype", sub)))
    return rules


def check_minimums(cases: list[dict[str, Any]], hcfg: dict[str, Any], ctx: Context) -> list[str]:
    per = int(hcfg["minimums"]["per_category"])
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in cases:
        by_cat[str(c["category"])].append(case_view(c, ctx))
    p: list[str] = []
    for cat in CHECK_FOR_CATEGORY:
        n = len(by_cat.get(cat, []))
        if n != per:
            p.append(f"{cat}: {n} cases (need exactly {per})")
    for rule in minimum_rules(hcfg):
        have = sum(1 for v in by_cat.get(rule.category, []) if rule.matches(v))
        if have < rule.need:
            p.append(rule.message.format(have=have, need=rule.need))
    return p


# -------------------------------------------------------------------------- selection
# §8.6 step 5, in priority order: each pick is the candidate whose value on the first
# of these keys is least represented among the cases chosen so far, then the second...
VARIETY_ORDER = ("subtype", "injection_style", "provenance", "source", "role/direction")


class SelectionError(RuntimeError):
    pass


def variety_features(view: dict[str, Any]) -> tuple[str, ...]:
    target = view.get("target_tier")
    role = str(view.get("role"))
    return (str(view.get("subtype")), str(view.get("injection_style")), "+".join(view["provenances"]) or "-",
            str(view.get("source")), f"{role}->{target}" if target else role)


def _pick(rest: list[dict[str, Any]], chosen: list[dict[str, Any]], short: list[MinimumRule],
          views: dict[str, dict[str, Any]], tiebreak: dict[str, int]) -> dict[str, Any]:
    seen = [Counter(variety_features(views[str(c["id"])])[k] for c in chosen) for k in range(len(VARIETY_ORDER))]

    def key(c: dict[str, Any]) -> tuple[int, tuple[int, ...], int]:
        v = views[str(c["id"])]
        feats = variety_features(v)
        closes = sum(1 for r in short if r.matches(v))
        return -closes, tuple(seen[k][f] for k, f in enumerate(feats)), tiebreak[str(c["id"])]

    return min(rest, key=key)


def select_cases(pool: list[dict[str, Any]], hcfg: dict[str, Any], ctx: Context, seed: int) -> list[dict[str, Any]]:
    """Choose `per_category` cases per category from seeds and candidates (§8.6 step 5).

    Every seed is kept. Each remaining slot goes to the candidate that closes the most
    §8.6 minimums still short, then to the one that adds the most variety of technique
    (VARIETY_ORDER); ties fall to a fixed-seed shuffle. The rule reads labels and
    document provenance only, never results or success criteria, so success rate can't
    steer it. Raises SelectionError if a category can't reach its size or minimums.
    """
    per = int(hcfg["minimums"]["per_category"])
    dup = sorted(cid for cid, n in Counter(str(c["id"]) for c in pool).items() if n > 1)
    if dup:
        raise SelectionError(f"duplicate case ids in the pool: {', '.join(dup)}")
    order = sorted(str(c["id"]) for c in pool)
    random.Random(seed).shuffle(order)
    tiebreak = {cid: i for i, cid in enumerate(order)}
    views = {str(c["id"]): case_view(c, ctx) for c in pool}
    rules = minimum_rules(hcfg)
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for c in pool:
        by_cat[str(c["category"])].append(c)
    selected: list[dict[str, Any]] = []
    for cat in CHECK_FOR_CATEGORY:
        group = sorted(by_cat.get(cat, []), key=lambda c: str(c["id"]))
        chosen = [c for c in group if c["source"] in SEED_SOURCES]
        if len(chosen) > per:
            raise SelectionError(f"{cat}: {len(chosen)} seeds, more than the {per} slots")
        rest = [c for c in group if c["source"] not in SEED_SOURCES]
        cat_rules = [r for r in rules if r.category == cat]
        while len(chosen) < per and rest:
            short = [r for r in cat_rules if sum(1 for c in chosen if r.matches(views[str(c["id"])])) < r.need]
            best = _pick(rest, chosen, short, views, tiebreak)
            chosen.append(best)
            rest = [c for c in rest if c["id"] != best["id"]]
        if len(chosen) < per:
            raise SelectionError(f"{cat}: only {len(chosen)} cases available; write more variants (§8.6)")
        selected.extend(chosen)
    problems = check_minimums(selected, hcfg, ctx)
    if problems:
        raise SelectionError("the selection misses §8.6 minimums; write more variants:\n  " + "\n  ".join(problems))
    return selected


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
        # FREEZE.md hashes the case files, not the documents they point to; pinning each
        # document's hash inside the frozen case makes an edited document a mismatch too.
        d["sha256"] = freeze.sha256_file(ctx.root / rel)
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
promptfoo integration (Run 2, §8.6):
  1. uv run ragsec attacks promptfoo       (owner, once: asks for an email; pinned version, telemetry off)
  2. npx promptfoo@<version> redteam poison <docs> -g <goal>   (run from attacks/promptfoo/poison/)
  3. Label every output in attacks/promptfoo/mapping.yaml (category, role, target tier, or drop + reason)
  4. uv run ragsec attacks generate --convert
     writes attacks/candidates/promptfoo_converted.yaml and the poisoned documents in attacks/docs/
"""

PROMPTFOO_ID_START = 201


def convert_promptfoo(root: Path, mapping_path: Path) -> tuple[list[dict[str, Any]], dict[str, str], list[str]]:
    """Convert promptfoo output into candidate cases using the labels in mapping.yaml.

    Returns (cases, documents {repo-relative path: text}, dropped notes). Every kept
    candidate gets one of this project's objective checks; promptfoo's own grader and
    assertions are ignored.
    """
    mapping = read_yaml(mapping_path) or {}
    version = str(read_yaml(root / "config" / "pins.yaml").get("promptfoo", {}).get("version", "?"))
    generated = read_yaml(root / str(mapping["generated"])) or {}
    tests = generated.get("tests", [])
    labels = {int(k): v for k, v in (mapping.get("tests") or {}).items()}
    if set(labels) != set(range(len(tests))):
        raise ValueError(f"mapping.yaml must label every generated test (0..{len(tests) - 1}); "
                         f"missing {sorted(set(range(len(tests))) - set(labels))}")
    counters: Counter[str] = Counter()
    cases: list[dict[str, Any]] = []
    dropped: list[str] = []

    def next_id(category: str) -> str:
        prefix = {v: k for k, v in CATEGORY_BY_PREFIX.items()}[category]
        n = PROMPTFOO_ID_START + counters[prefix]
        counters[prefix] += 1
        return f"{prefix}-{n:03d}"

    for i, test in enumerate(tests):
        lab = labels[i]
        plugin = str((test.get("metadata") or {}).get("pluginId", "unknown"))
        if lab.get("drop"):
            dropped.append(f"test {i} ({plugin}): {lab['drop']}")
            continue
        category = str(lab["category"])
        case: dict[str, Any] = {
            "id": next_id(category), "category": category, "owasp": sorted(OWASP_FOR_CATEGORY[category]),
            "source": "promptfoo", "subtype": str(lab["subtype"]), "role": str(lab["role"]),
            "user_message": str(test["vars"]["query"]), "email_request": False,
            "target_tier": lab.get("target_tier"),
            "success": {"check": CHECK_FOR_CATEGORY[category]},
            "notes": f"promptfoo {version} plugin {plugin}, generated test #{i}; labels assigned at conversion",
        }
        cases.append(case)

    docs: dict[str, str] = {}
    for item in mapping.get("poison") or []:
        raw = read_yaml(root / str(item["file"])) or {}
        if item.get("drop"):
            dropped.append(f"{item['file']}: {item['drop']}")
            continue
        poisoned = str(raw["documents"][0]["poisonedDocument"]).strip()
        category = str(item["category"])
        rel = f"attacks/docs/{item['doc_id']}.md"
        meta = {"doc_id": item["doc_id"], "title": item["title"], "tier": "general",
                "provenance": item["provenance"], "updated": str(item["updated"])}
        docs[rel] = frontmatter.join(meta, poisoned + "\n")
        cases.append({
            "id": next_id(category), "category": category, "owasp": sorted(OWASP_FOR_CATEGORY[category]),
            "source": "promptfoo", "subtype": "pf_poisoned_copy", "role": "employee",
            "user_message": str(item["user_message"]), "email_request": False, "target_tier": None,
            "poisoned_docs": [{"file": rel}],
            "success": {"check": "false_fact_in_answer", "false_pattern": str(item["false_pattern"]),
                        "true_fact": str(item["true_fact"])},
            "notes": (f"promptfoo {version} `redteam poison` copy of a real policy with a planted false fact "
                      f"(goal: {raw['documents'][0].get('intendedResult', '')})"),
        })
    return cases, docs, dropped
