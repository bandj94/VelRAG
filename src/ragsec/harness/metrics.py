"""Aggregate raw trial results into the metrics of spec §10.3."""

from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from ragsec.harness import paths as hp
from ragsec.harness import stats

CATEGORIES = ("direct_injection", "hidden_context", "indirect_phishing", "cross_role_leak",
              "retrieval_hijack", "markdown_exfil", "tool_misuse", "resource_exhaustion")
CATEGORY_CODE = {c: f"A{i}" for i, c in enumerate(CATEGORIES, start=1)}


@dataclass
class Run:
    meta: dict[str, Any]
    records: list[dict[str, Any]]


def load_runs(root: Path | None = None) -> list[Run]:
    runs = []
    raw = hp.raw_results(root)
    for meta_path in sorted(raw.glob("*.meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        data_path = raw / f"{meta['run_id']}.jsonl"
        records = []
        if data_path.is_file():
            records = [json.loads(x) for x in data_path.read_text(encoding="utf-8").splitlines() if x.strip()]
        runs.append(Run(meta, records))
    return runs


def collect(runs: list[Run]) -> dict[tuple[str, str, str], list[dict[str, Any]]]:
    """(model, preset, suite) -> records, keeping the latest run's record per (case, trial)."""
    ordered = sorted(runs, key=lambda r: str(r.meta.get("started_at", "")))
    table: dict[tuple[str, str, str], dict[tuple[str, int], dict[str, Any]]] = defaultdict(dict)
    for run in ordered:
        for rec in run.records:
            if not rec.get("scored", True):
                continue
            key = (str(rec["model"]), str(rec["preset"]), str(rec["suite"]))
            table[key][(str(rec["case_id"]), int(rec["trial"]))] = rec
    return {k: list(v.values()) for k, v in table.items()}


def cases_of(records: list[dict[str, Any]], category: str | None = None,
             success_key: str = "success") -> stats.Cases:
    out: stats.Cases = defaultdict(list)
    for r in records:
        if category is not None and r.get("category") != category:
            continue
        val = r.get(success_key)
        if val is None:
            continue
        out[str(r["case_id"])].append(1 if val else 0)
    return dict(out)


def category_row(records: list[dict[str, Any]], category: str, success_key: str = "success",
                 n_resamples: int = 10000, seed: int = 1234) -> dict[str, Any]:
    cases = cases_of(records, category, success_key)
    trials = sum(len(v) for v in cases.values())
    succ = sum(sum(v) for v in cases.values())
    lo, hi = stats.cluster_bootstrap_ci(cases, n_resamples, seed) if cases else (float("nan"), float("nan"))
    return {
        "category": category, "code": CATEGORY_CODE.get(category, "?"), "cases": len(cases), "trials": trials,
        "successes": succ, "asr": (succ / trials) if trials else float("nan"), "ci_lo": lo, "ci_hi": hi,
        "case_any_success_share": (stats.cases_with_success(cases) / len(cases)) if cases else float("nan"),
    }


def benign_summary(records: list[dict[str, Any]], n_resamples: int = 10000, seed: int = 1234) -> dict[str, Any]:
    recs = [r for r in records if r.get("benign")]
    n = len(recs)
    if n == 0:
        return {"trials": 0}
    acc = sum(1 for r in recs if r["benign"]["accurate"])
    ref = sum(1 for r in recs if r["benign"]["refusal"])
    near = [r for r in recs if r["benign"]["near_miss"]]
    cases: stats.Cases = defaultdict(list)
    for r in recs:
        cases[str(r["case_id"])].append(1 if r["benign"]["accurate"] else 0)
    lo, hi = stats.cluster_bootstrap_ci(dict(cases), n_resamples, seed)
    safety = {k: sum(1 for r in recs if r["benign"]["safety"][k]) / n
              for k in ("unasked_email", "email_to_other", "unauthorized_canary", "any")}
    return {
        "trials": n, "accurate": acc, "accuracy": acc / n, "accuracy_ci": (lo, hi),
        "refusals": ref, "false_refusal_rate": ref / n,
        "near_miss_trials": len(near),
        "near_miss_accuracy": (sum(1 for r in near if r["benign"]["accurate"]) / len(near)) if near else float("nan"),
        "near_miss_refusal_rate": (sum(1 for r in near if r["benign"]["refusal"]) / len(near)) if near else float("nan"),
        "safety": safety,
        "pipeline_failures": sum(1 for r in recs if r["benign"].get("pipeline_failure")),
    }


def latency_summary(records: list[dict[str, Any]]) -> dict[str, float]:
    vals = [float(r["diagnostics"]["virtual_latency_seconds"]) for r in records
            if (r.get("diagnostics") or {}).get("virtual_latency_seconds") is not None]
    if not vals:
        return {"n": 0}
    arr = np.array(vals)
    return {"n": len(vals), "median": float(np.median(arr)), "p95": float(np.quantile(arr, 0.95)),
            "total_seconds": float(arr.sum())}


def resources_summary(records: list[dict[str, Any]]) -> dict[str, float]:
    diags = [r.get("diagnostics") or {} for r in records]
    n = len(diags) or 1
    return {
        "output_tokens_per_trial": sum(int(d.get("output_tokens") or 0) for d in diags) / n,
        "model_calls_per_trial": sum(int(d.get("model_calls") or 0) for d in diags) / n,
        "tool_attempts_per_trial": sum(int(d.get("tool_call_attempts") or 0) for d in diags) / n,
        "context_overflows": sum(1 for d in diags if d.get("context_overflow")),
        "errors": sum(1 for r in records if int(r.get("http_status") or 0) >= 500),
        "cache_hit_rate": (sum(int(d.get("cache_hits") or 0) for d in diags)
                           / max(1, sum(int(d.get("model_calls") or 0) for d in diags))),
    }
