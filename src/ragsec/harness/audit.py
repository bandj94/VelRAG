"""Check audit (spec §10.5).

``ragsec audit sample`` draws up to 10 successful trials per category (Model A,
baseline, dev; at most 2 per case; fixed seed) and writes
results/audit/sample.yaml with what each check saw. The user labels each sample in
results/audit/labels.yaml (user-owned) as correct, false_positive, or unclear.
``ragsec audit score`` reports how often the checks were right, per category. A
category with false positives gets a note next to its results, never a silent fix.
"""

from __future__ import annotations

import random
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

import yaml

from ragsec.harness import metrics
from ragsec.harness import paths as hp
from ragsec.harness.data import read_yaml

LABELS = ("correct", "false_positive", "unclear")


def sample(root: Path | None = None, model: str = "A", per_category: int = 10, per_case: int = 2,
           seed: int = 777) -> Path:
    r = root or hp.root()
    data = metrics.collect(metrics.load_runs(r))
    recs = [x for x in data.get((model, "baseline", "dev"), []) if x.get("success")]
    if not recs:
        raise RuntimeError("no successful baseline dev trials for this model yet")
    rng = random.Random(seed)
    by_cat: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rec in sorted(recs, key=lambda x: (x["case_id"], x["trial"])):
        by_cat[str(rec["category"])].append(rec)
    case_cache: dict[str, dict[str, Any]] = {}
    for f in (hp.frozen(r) / "dev.yaml",):
        if f.is_file():
            for c in yaml.safe_load(f.read_text(encoding="utf-8")) or []:
                case_cache[str(c["id"])] = c
    samples = []
    for cat in sorted(by_cat):
        pool = by_cat[cat]
        rng.shuffle(pool)
        per: Counter[str] = Counter()
        taken = 0
        for rec in pool:
            if taken >= per_category:
                break
            if per[rec["case_id"]] >= per_case:
                continue
            per[rec["case_id"]] += 1
            taken += 1
            case = case_cache.get(str(rec["case_id"]), {})
            docs = []
            for d in case.get("poisoned_docs") or []:
                path = r / str(d["file"])
                docs.append({"file": str(d["file"]), "text": path.read_text(encoding="utf-8") if path.is_file() else ""})
            attacker_requests = [q for q in rec.get("browser_requests") or [] if "attacker" in str(q.get("url", ""))
                                 or ":8765" in str(q.get("url", ""))]
            samples.append({
                "sample_id": f"{rec['case_id']}-t{rec['trial']}",
                "run_id": rec["run_id"], "case_id": rec["case_id"], "category": cat, "trial": rec["trial"],
                "role": rec.get("role"), "message": case.get("user_message"), "poisoned_docs": docs,
                "delivered_answer": rec.get("answer"), "emails": rec.get("emails"),
                "attacker_requests": attacker_requests,
                "check": rec.get("check"), "check_reason": (rec.get("check_result") or {}).get("reason"),
                "check_detail": (rec.get("check_result") or {}).get("detail"),
            })
    out = hp.audit(r) / "sample.yaml"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(samples, sort_keys=False, allow_unicode=True, width=120), encoding="utf-8", newline="\n")
    return out


def load_labels(path: Path) -> dict[str, dict[str, Any]]:
    raw = read_yaml(path) or {}
    if isinstance(raw, list):
        return {str(x.get("id") or x.get("sample_id")): x for x in raw}
    return {str(k): (v if isinstance(v, dict) else {"label": v}) for k, v in raw.items()}


def score(root: Path | None = None) -> Path:
    r = root or hp.root()
    samples = read_yaml(hp.audit(r) / "sample.yaml") or []
    labels_path = hp.audit(r) / "labels.yaml"
    if not labels_path.is_file():
        raise RuntimeError("results/audit/labels.yaml is missing; the user writes it (it is user-owned)")
    labels = load_labels(labels_path)
    per: dict[str, Counter[str]] = defaultdict(Counter)
    missing = []
    for s in samples:
        lab = labels.get(str(s["sample_id"]), {}).get("label")
        if lab not in LABELS:
            missing.append(s["sample_id"])
            continue
        per[str(s["category"])][str(lab)] += 1
    lines = ["| Category | Samples | Correct | False positive | Unclear | Checks right |", "|---|---|---|---|---|---|"]
    for cat in sorted(per):
        c = per[cat]
        n = sum(c.values())
        lines.append(f"| {cat} | {n} | {c['correct']} | {c['false_positive']} | {c['unclear']} | "
                     f"{100 * c['correct'] / n:.0f}% |")
        if c["false_positive"]:
            lines.append(f"| ↳ note | | | | | {cat} has false positives: see its results with this caveat |")
    if missing:
        lines.append(f"\nUnlabelled or invalid labels: {', '.join(map(str, missing))}")
    out = hp.summary(r) / "audit.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return out
