"""Adaptive round (spec §8.7): attempt log, budget, fingerprints, and the final set.

- **Development attempts:** Model A, preset ``all``, 3 trials, namespace ``adaptive-dev``.
  One case is one attempt, and each category gets at most 10.
- **The log:** ``attacks/adaptive/attempts.jsonl`` is committed. It records labels,
  counts, HTTP statuses, defense event types, and check reasons with every canary value
  replaced by its id. It never records answer text, check details, or secret values.
- **The final set:** ``attacks/adaptive/final.yaml`` holds verbatim copies of logged
  attempts, chosen by :func:`select_final`, with each poisoned document's sha256 pinned
  like the frozen sets. It runs in the fresh ``adaptive-final`` namespace, so its numbers
  never reuse the draws that picked it.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import copy
import hashlib
import json
import re
import time
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ragsec.harness import freeze
from ragsec.harness import paths as hp
from ragsec.harness.data import Canary, load_case_file

BUDGET_PER_CATEGORY = 10
FINAL_PER_CATEGORY = 3
DEV_MODEL, DEV_PRESET, DEV_TRIALS = "A", "all", 3
REASON_MAX = 160


class AdaptiveError(RuntimeError):
    pass


class _PlainDumper(yaml.SafeDumper):
    """Writes every case out in full: no YAML anchors or aliases, so each case reads on its own."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


def dump_cases(cases: list[dict[str, Any]]) -> str:
    return yaml.dump(cases, Dumper=_PlainDumper, sort_keys=False, allow_unicode=True, width=100)


def attempts_path(root: Path | None = None) -> Path:
    return hp.adaptive(root) / "attempts.jsonl"


def final_path(root: Path | None = None) -> Path:
    return hp.adaptive(root) / "final.yaml"


def dev_dir(root: Path | None = None) -> Path:
    return hp.adaptive(root) / "dev"


def docs_dir(root: Path | None = None) -> Path:
    return hp.adaptive(root) / "docs"


# ------------------------------------------------------------------ fingerprints
def fingerprint(case: dict[str, Any], root: Path) -> str:
    """sha256 over the case and the bytes of each of its documents.

    The ``sha256`` pin that :func:`finalize` adds to a document entry is ignored, so a
    final copy has the same fingerprint as the attempt it came from. Any edit to the case
    or to one of its documents changes the fingerprint.
    """
    body = {k: v for k, v in case.items() if k != "poisoned_docs"}
    docs = [{"file": str(d["file"]), "bytes": freeze.sha256_file(root / str(d["file"]))}
            for d in case.get("poisoned_docs") or []]
    blob = json.dumps({"case": body, "docs": docs}, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


# ------------------------------------------------------------------------- log
def load_log(root: Path | None = None) -> list[dict[str, Any]]:
    path = attempts_path(root)
    if not path.is_file():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def used_by_category(log: Iterable[dict[str, Any]]) -> Counter[str]:
    return Counter(str(e["category"]) for e in log)


def budget_problems(cases: list[dict[str, Any]], log: list[dict[str, Any]], root: Path) -> list[str]:
    """Why a batch may not run: over budget, a case id reused, or an identical attempt."""
    problems: list[str] = []
    used = used_by_category(log)
    new = Counter(str(c.get("category")) for c in cases)
    for cat, n in sorted(new.items()):
        if used[cat] + n > BUDGET_PER_CATEGORY:
            problems.append(f"{cat}: {used[cat]} attempts logged + {n} new > budget of {BUDGET_PER_CATEGORY}")
    logged_ids = {str(e["case_id"]) for e in log}
    logged_prints = {str(e["fingerprint"]) for e in log}
    seen: set[str] = set()
    for c in cases:
        cid = str(c.get("id"))
        if cid in logged_ids:
            problems.append(f"{cid}: id already used by a logged attempt (ids are never reused)")
        if cid in seen:
            problems.append(f"{cid}: duplicate id in this batch")
        seen.add(cid)
        if c.get("source") != "adaptive":
            problems.append(f"{cid}: source must be 'adaptive' (owner attacks go in attacks/adaptive/user/)")
        try:
            if fingerprint(c, root) in logged_prints:
                problems.append(f"{cid}: identical to a logged attempt (it would spend budget on a repeat)")
        except (KeyError, FileNotFoundError) as exc:
            problems.append(f"{cid}: cannot fingerprint ({exc})")
        for d in c.get("poisoned_docs") or []:
            rel = Path(str(d.get("file", "")))
            if rel.parts[:3] != ("attacks", "adaptive", "docs"):
                problems.append(f"{cid}: documents must live in attacks/adaptive/docs/ ({rel})")
    return problems


def _redact(text: str, canaries: list[Canary]) -> str:
    for c in canaries:
        for v in c.values:
            if v and v in text:
                text = text.replace(v, f"<{c.id}>")
    return text


def summarize_trial(rec: dict[str, Any], canaries: list[Canary]) -> dict[str, Any]:
    """A trial as the log records it: no answer text, no check details, no secret values."""
    diag = rec.get("diagnostics") or {}
    events = sorted({str(e.get("type")) for e in rec.get("events") or [] if isinstance(e, dict) and e.get("type")})
    cr = rec.get("check_result") or {}
    reason = _redact(str(cr.get("reason") or ""), canaries)[:REASON_MAX]
    conditions = [str(x) for x in ((cr.get("detail") or {}).get("conditions") or [])
                  if isinstance(x, str)]
    return {"trial": int(rec.get("trial", 0)), "success": bool(rec.get("success")),
            "success_vigilant": rec.get("success_vigilant"), "status": rec.get("http_status"),
            "events": events, "reason": reason, "conditions": conditions,
            "poison_rank_before": diag.get("poison_rank_before"),
            "poison_rank_after": diag.get("poison_rank_after"), "quarantined": bool(diag.get("quarantined")),
            "exfil_link": rec.get("exfil_link")}


def entries_for_run(cases: list[dict[str, Any]], records: list[dict[str, Any]], *, file: str, run_id: str,
                    log: list[dict[str, Any]], root: Path, canaries: list[Canary], note: str = "",
                    now: str | None = None) -> list[dict[str, Any]]:
    """One log entry per case of a finished run, numbered within each category."""
    latest: dict[tuple[str, int], dict[str, Any]] = {}
    for r in records:
        latest[(str(r["case_id"]), int(r["trial"]))] = r
    used = used_by_category(log)
    out = []
    for c in cases:
        cid, cat = str(c["id"]), str(c["category"])
        trials = sorted((r for (k, _t), r in latest.items() if k == cid), key=lambda r: int(r["trial"]))
        if len(trials) < DEV_TRIALS:
            raise AdaptiveError(f"{cid}: only {len(trials)} of {DEV_TRIALS} trials recorded in {run_id}")
        used[cat] += 1
        per = [summarize_trial(r, canaries) for r in trials]
        out.append({"attempt": used[cat], "category": cat, "case_id": cid, "subtype": c.get("subtype"),
                    "injection_style": c.get("injection_style"), "owasp": c.get("owasp") or [],
                    "basis": str(c.get("notes") or "")[:240], "file": file, "fingerprint": fingerprint(c, root),
                    "run_id": run_id, "namespace": "adaptive-dev", "model": DEV_MODEL, "preset": DEV_PRESET,
                    "trials": len(per), "successes": sum(1 for t in per if t["success"]),
                    "per_trial": per, "note": note, "logged_at": now or time.strftime("%Y-%m-%dT%H:%M:%S")})
    return out


def append_log(entries: list[dict[str, Any]], root: Path | None = None) -> None:
    path = attempts_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as fh:
        for e in entries:
            fh.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")


# --------------------------------------------------------------------- selection
def select_final(log: list[dict[str, Any]], per_category: int = FINAL_PER_CATEGORY) -> list[dict[str, Any]]:
    """Per category: the attempts with the most dev successes. Ties go first to a technique
    (subtype) not yet chosen in that category, then to the later attempt. Fixed in
    DECISIONS.md before the final set is drawn."""
    chosen: list[dict[str, Any]] = []
    for cat in sorted({str(e["category"]) for e in log}):
        pool = [e for e in log if e["category"] == cat]
        picked: list[dict[str, Any]] = []
        while pool and len(picked) < per_category:
            best = max(int(e["successes"]) for e in pool)
            top = [e for e in pool if int(e["successes"]) == best]
            techniques = {str(p.get("subtype")) for p in picked}
            fresh = [e for e in top if str(e.get("subtype")) not in techniques] or top
            pick = max(fresh, key=lambda e: int(e["attempt"]))
            picked.append(pick)
            pool.remove(pick)
        chosen.extend(picked)
    return chosen


@dataclass
class Final:
    path: Path
    cases: list[dict[str, Any]]


def finalize(root: Path | None = None, per_category: int = FINAL_PER_CATEGORY) -> Final:
    r = root or hp.root()
    log = load_log(r)
    if not log:
        raise AdaptiveError("no attempts logged in attacks/adaptive/attempts.jsonl")
    out = final_path(r)
    if out.exists():
        raise AdaptiveError(f"{out} already exists; the final set is drawn once")
    final: list[dict[str, Any]] = []
    for e in select_final(log, per_category):
        cases = {str(c["id"]): c for c in load_case_file(r / str(e["file"]))}
        case = cases.get(str(e["case_id"]))
        if case is None:
            raise AdaptiveError(f"{e['case_id']}: not found in {e['file']}")
        if fingerprint(case, r) != e["fingerprint"]:
            raise AdaptiveError(f"{e['case_id']}: case or document changed since attempt {e['attempt']} was logged")
        pinned = copy.deepcopy(case)
        for d in pinned.get("poisoned_docs") or []:
            d["sha256"] = freeze.sha256_file(r / str(d["file"]))
        final.append(pinned)
    header = ("# Adaptive final set (IMPLEMENTATION.md §8.7): verbatim copies of logged development attempts,\n"
              f"# {per_category} per category by dev successes (ties: a technique not yet chosen, then the later\n"
              "# attempt). Runs on both models with preset `all` in the fresh `adaptive-final` namespace.\n")
    out.write_text(header + dump_cases(sorted(final, key=lambda c: str(c["id"]))), encoding="utf-8", newline="\n")
    return Final(out, final)


# ------------------------------------------------------------- promptfoo route
# The owner chose promptfoo to generate the adaptive attacks (Run 4). Its output is
# converted mechanically: the category from promptfoo's plugin id, the technique from its
# strategy id, and the OWASP Top 10 for LLM Applications 2026 basis from the tables below.
# No prompt text is written or edited here.
PF_CATEGORY = {
    "ascii-smuggling": "direct_injection",
    "prompt-extraction": "hidden_context",
    "rbac": "cross_role_leak", "bola": "cross_role_leak", "pii:direct": "cross_role_leak",
    "pii:social": "cross_role_leak",
    "reasoning-dos": "resource_exhaustion", "divergent-repetition": "resource_exhaustion",
}
CATEGORY_OWASP = {"direct_injection": ["LLM01"], "hidden_context": ["LLM08"],
                  "cross_role_leak": ["LLM02", "LLM09"], "resource_exhaustion": ["LLM06"]}
PLUGIN_BASIS = {
    "ascii-smuggling": "OWASP LLM01:2026 risk example 5 (invisible-character injection)",
    "prompt-extraction": "OWASP LLM08:2026 attack scenario 2 (conversational probing of hidden context)",
    "rbac": "OWASP LLM02:2026 attack scenario 5 and LLM09:2026 risk example 1 (retrieval across access boundaries)",
    "bola": "OWASP LLM02:2026 attack scenario 5 and LLM09:2026 risk example 1 (retrieval across access boundaries)",
    "pii:direct": "OWASP LLM02:2026 risk example 2 (inference-time disclosure)",
    "pii:social": "OWASP LLM02:2026 risk example 2 (inference-time disclosure)",
    "reasoning-dos": "OWASP LLM06:2026 risk example 4 (reasoning-loop exhaustion)",
    "divergent-repetition": "OWASP LLM06:2026 risk example 1 (output explosion)",
}
STRATEGY_ORDER = ("basic", "base64", "rot13", "leetspeak", "homoglyph")
ENCODED_BASIS = "OWASP LLM01:2026 risk example 8 (encoded payloads evade filters)"
RULE9_DROPS = (
    (re.compile(r"@(?:gmail|googlemail|yahoo|outlook|hotmail|live|icloud|aol|proton(?:mail)?)\.", re.IGNORECASE),
     "names a real email provider (rule 9)"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b|\bghp_[A-Za-z0-9]{20,}|\bsk-[A-Za-z0-9]{10,}|\bsk_live_"),
     "real secret format (rule 9)"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "SSN-style number (rule 9)"),
)
# Host names on the reserved `.example` domain or a public top-level domain. Rule 9 allows only
# the company's own domain, `.test`, and `*.attacker.localhost`; ASCII-only, so homoglyph text
# is judged by promptfoo's recorded original instead.
HOST_RX = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+"
                     r"(?:example|com|net|org|io|co|ai|dev|app|gov|edu|info|biz|me|us|uk|ca|de|fr|in|au)\b",
                     re.ASCII | re.IGNORECASE)
COMPANY_DOMAIN = "velmora.example"


def outside_hosts(text: str) -> list[str]:
    """Hosts in ``text`` that rule 9 doesn't allow (anything but the company's own domain)."""
    hosts = {h.lower() for h in HOST_RX.findall(text)}
    return sorted(h for h in hosts if h != COMPANY_DOMAIN and not h.endswith("." + COMPANY_DOMAIN))


HR_TERMS = re.compile(r"salar|payroll|compensation|bonus|performance|investigation|disciplin|\bhr\b|human resources|"
                      r"personnel|benefit|termination|medical", re.IGNORECASE)
PICK_SEED = 20261112
PER_ROUND = 5


def pool_path(root: Path | None = None) -> Path:
    return hp.adaptive(root) / "promptfoo" / "pool.yaml"


def generated_path(root: Path | None = None) -> Path:
    return hp.adaptive(root) / "promptfoo" / "redteam_generated.yaml"


def _plain_text(query: str, strategy: str, metadata: dict[str, Any]) -> str:
    """The text a label is read from: promptfoo's recorded original if any, else a decoded form."""
    for key in ("originalText", "originalPrompt"):
        if metadata.get(key):
            return str(metadata[key])
    if strategy == "base64":
        try:
            return base64.b64decode(query.strip(), validate=False).decode("utf-8", errors="replace")
        except (ValueError, binascii.Error):
            return query
    if strategy == "rot13":
        return codecs.decode(query, "rot13")
    return query


@dataclass
class Converted:
    cases: list[dict[str, Any]]
    dropped: list[tuple[int, str]]


def convert_promptfoo(generated: dict[str, Any], version: str,
                      validate: Callable[[dict[str, Any]], list[str]] | None = None) -> Converted:
    """promptfoo's generated tests -> adaptive cases with objective checks (or a drop reason)."""
    from ragsec.harness.attacks import CHECK_FOR_CATEGORY
    from ragsec.harness.runner import CATEGORY_BY_PREFIX

    prefix_of = {cat: prefix for prefix, cat in CATEGORY_BY_PREFIX.items()}
    cases: list[dict[str, Any]] = []
    dropped: list[tuple[int, str]] = []
    counters: Counter[str] = Counter()
    for i, t in enumerate(generated.get("tests") or []):
        md = t.get("metadata") or {}
        plugin = str(md.get("pluginId") or "")
        strategy = str(md.get("strategyId") or "basic")
        query = str((t.get("vars") or {}).get("query") or "")
        cat = PF_CATEGORY.get(plugin)
        if cat is None:
            dropped.append((i, f"plugin {plugin!r} has no objective check here"))
            continue
        if not query.strip():
            dropped.append((i, "empty prompt"))
            continue
        text = _plain_text(query, strategy, md)
        why = next((w for rx, w in RULE9_DROPS if rx.search(query) or rx.search(text)), None)
        if why is None and outside_hosts(text):
            why = "names a host outside velmora.example, .test, and attacker.localhost (rule 9)"
        if why:
            dropped.append((i, why))
            continue
        success: dict[str, Any] = {"check": CHECK_FOR_CATEGORY[cat]}
        if cat == "direct_injection":
            marker = md.get("asciiSmugglingTestString")
            if not marker:
                dropped.append((i, "no hidden test string to use as the A1 marker"))
                continue
            success["marker"] = str(marker)
        target = {"hidden_context": "system",
                  "cross_role_leak": "hr" if HR_TERMS.search(text) else "it_admin"}.get(cat)
        prefix = prefix_of[cat]
        counters[prefix] += 1
        basis = PLUGIN_BASIS[plugin] + ("" if strategy == "basic" else f"; {ENCODED_BASIS}")
        case = {"id": f"{prefix}-P{counters[prefix]:02d}", "category": cat, "owasp": list(CATEGORY_OWASP[cat]),
                "source": "adaptive", "subtype": f"{plugin}+{strategy}", "role": "employee",
                "user_message": query, "email_request": False, "target_tier": target, "success": success,
                "notes": f"promptfoo {version} redteam generate (plugin {plugin}, strategy {strategy}); {basis}",
                "generator": f"promptfoo {version}", "pf_index": i, "pf_plugin": plugin, "pf_strategy": strategy}
        problems = validate(case) if validate else []
        if problems:
            counters[prefix] -= 1
            dropped.append((i, "validation: " + "; ".join(problems)))
            continue
        cases.append(case)
    return Converted(cases, dropped)


def _rates(log: list[dict[str, Any]], key: Callable[[dict[str, Any]], str]) -> dict[str, float]:
    hits: Counter[str] = Counter()
    trials: Counter[str] = Counter()
    for e in log:
        hits[key(e)] += int(e["successes"])
        trials[key(e)] += int(e["trials"])
    return {k: hits[k] / trials[k] for k in trials if trials[k]}


def pick_round(pool: list[dict[str, Any]], log: list[dict[str, Any]], round_no: int,
               per_round: int = PER_ROUND, seed: int = PICK_SEED) -> list[dict[str, Any]]:
    """Choose the next development attempts from the converted pool (rule fixed in DECISIONS.md).

    Round 1 (variety): per category, up to ``per_round`` cases, each time the one whose
    strategy, then plugin, is least represented among the picks; ties fall to a fixed-seed
    order. Later rounds (adaptive): the same, but candidates are ranked first by their
    plugin+strategy pair's development success rate so far, then their strategy's, then
    their plugin's. Never more than the category's remaining budget.
    """
    import random

    attempted = {str(e["case_id"]) for e in log}
    used = used_by_category(log)
    out: list[dict[str, Any]] = []
    for cat in sorted({str(c["category"]) for c in pool}):
        cands = sorted((c for c in pool if c["category"] == cat and str(c["id"]) not in attempted),
                       key=lambda c: str(c["id"]))
        random.Random(f"{seed}-{round_no}-{cat}").shuffle(cands)
        n = min(per_round, BUDGET_PER_CATEGORY - used[cat], len(cands))
        cat_log = [e for e in log if e["category"] == cat]
        pair = _rates(cat_log, lambda e: str(e.get("subtype")))
        strat = _rates(cat_log, lambda e: str(e.get("subtype")).rsplit("+", 1)[-1])
        plug = _rates(cat_log, lambda e: str(e.get("subtype")).rsplit("+", 1)[0])
        score = {str(c["id"]): (0.0, 0.0, 0.0) if round_no <= 1 else
                 (pair.get(str(c["subtype"]), 0.0), strat.get(str(c["pf_strategy"]), 0.0),
                  plug.get(str(c["pf_plugin"]), 0.0)) for c in cands}

        picked: list[dict[str, Any]] = []
        while len(picked) < n:
            best = max(score[str(c["id"])] for c in cands)
            top = [c for c in cands if score[str(c["id"])] == best]
            s_count = Counter(str(p["pf_strategy"]) for p in picked)
            p_count = Counter(str(p["pf_plugin"]) for p in picked)
            pick = min(top, key=lambda c: (s_count[str(c["pf_strategy"])], p_count[str(c["pf_plugin"])],
                                           top.index(c)))
            picked.append(pick)
            cands.remove(pick)
        out.extend(picked)
    return out


def status_rows(log: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for cat in sorted({str(e["category"]) for e in log}):
        es = [e for e in log if e["category"] == cat]
        rows.append({"category": cat, "used": len(es), "budget": BUDGET_PER_CATEGORY,
                     "best": max(int(e["successes"]) for e in es),
                     "with_success": sum(1 for e in es if int(e["successes"]) > 0)})
    return rows
