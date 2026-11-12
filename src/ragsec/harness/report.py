"""``ragsec report`` (spec §15.1, §15.2).

Writes summary CSVs and charts to results/summary/, and refreshes the generated
blocks of REPORT.md (``<!-- GENERATED:BEGIN name -->`` … ``END``). It never touches
the two user-owned blocks: it hashes each before writing and refuses to save if
either changed (tested).
"""

from __future__ import annotations

import csv
import hashlib
import json
import math
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

from ragsec.harness import metrics, predictions, stats
from ragsec.harness import paths as hp
from ragsec.harness.metrics import CATEGORIES, CATEGORY_CODE

USER_BLOCK = re.compile(r"<!-- USER-OWNED:BEGIN ([\w-]+) -->.*?<!-- USER-OWNED:END \1 -->", re.DOTALL)
GEN_BLOCK = re.compile(r"(<!-- GENERATED:BEGIN ([\w-]+) -->)(.*?)(<!-- GENERATED:END \2 -->)", re.DOTALL)
REQUIRED_USER_BLOCKS = {"conclusions", "recommendations"}
SINGLE_PRESETS = ["d1", "d2", "d3", "d4", "d5", "d6", "d7", "all"]
ABLATION_PRESETS = [f"all_minus_d{i}" for i in range(1, 8)]
PRESET_ORDER = ["baseline", *SINGLE_PRESETS, *ABLATION_PRESETS]
SUITE_ORDER = ["dev", "heldout", "adaptive", "benign"]
LOAD_PRESETS = ["baseline", "d7", "all"]  # §8.8's presets, in report order

# A turn's virtual latency by stage (§10.2): model time is what Ollama reported for the
# generation; every other stage is measured wall time. D1 runs inside retrieval, D4 inside
# prompt building, D3 inside the tool step; D6 works at ingestion, outside any turn.
STAGES = ("model", "retrieval", "D5", "prompt", "tool", "D2", "other")
STAGE_OF = {"retrieve": "retrieval", "d5_message": "D5", "d5_chunks": "D5", "build_prompt": "prompt",
            "tool": "tool", "d2_output": "D2"}

# Chart colors: the dataviz skill's reference palette, light mode. Sequential blue for
# magnitude, blue <-> red around a gray midpoint for signed change, categorical slots
# 1 and 2 (blue, orange) for two series; text stays in ink colors.
SURFACE, INK, INK2, MUTED, GRID, AXIS = "#fcfcfb", "#0b0b0b", "#52514e", "#898781", "#e1e0d9", "#c3c2b7"
SERIES = ("#2a78d6", "#eb6834")
SEQ_BLUE = ("#cde2fb", "#9ec5f4", "#6da7ec", "#3987e5", "#256abf", "#184f95", "#0d366b")
DIVERGING = ("#2a78d6", "#f0efec", "#e34948")


def stage_split(rec: dict[str, Any]) -> dict[str, float]:
    """Seconds per stage for one turn; the parts sum to its virtual latency."""
    t = (rec.get("diagnostics") or {}).get("timings") or {}
    out = dict.fromkeys(STAGES, 0.0)
    out["model"] = sum(float(x) for x in t.get("model_recorded_seconds") or [])
    for name, secs in (t.get("stage_wall_seconds") or {}).items():
        out[STAGE_OF.get(name, "other")] += float(secs)
    return out


def _order(preset: str) -> int:
    return PRESET_ORDER.index(preset) if preset in PRESET_ORDER else len(PRESET_ORDER)


def _keys(data: dict[tuple[str, str, str], Any], suites: list[str]) -> list[tuple[str, str, str]]:
    """(model, preset, suite) keys for the given suites, in model, suite, preset order."""
    return sorted((k for k in data if k[2] in suites), key=lambda k: (k[0], suites.index(k[2]), _order(k[1]), k[1]))


class ReportError(RuntimeError):
    pass


# --------------------------------------------------------------------------- REPORT.md
def user_block_hashes(text: str) -> dict[str, str]:
    return {m.group(1): hashlib.sha256(m.group(0).encode("utf-8")).hexdigest() for m in USER_BLOCK.finditer(text)}


def update_report_md(path: Path, sections: dict[str, str]) -> list[str]:
    """Replace generated blocks; keep everything else byte-identical. Returns updated block names."""
    original = path.read_text(encoding="utf-8")
    before = user_block_hashes(original)
    if set(before) != REQUIRED_USER_BLOCKS:
        raise ReportError(f"REPORT.md must contain exactly the user-owned blocks {sorted(REQUIRED_USER_BLOCKS)}; "
                          f"found {sorted(before)}. Refusing to write.")
    updated: list[str] = []

    def repl(m: re.Match[str]) -> str:
        name = m.group(2)
        if name not in sections:
            return m.group(0)
        content = sections[name].replace("<!--", "&lt;!--")
        updated.append(name)
        return f"{m.group(1)}\n{content.rstrip()}\n{m.group(4)}"

    new = GEN_BLOCK.sub(repl, original)
    after = user_block_hashes(new)
    if after != before:
        raise ReportError("a user-owned block of REPORT.md would change; refusing to save")
    path.write_text(new, encoding="utf-8", newline="\n")
    return updated


# ------------------------------------------------------------------------------ helpers
def _fmt(x: float | None, pct: bool = True) -> str:
    if x is None or (isinstance(x, float) and math.isnan(x)):
        return "—"
    return f"{100 * x:.1f}%" if pct else f"{x:.3f}"


def _secs(x: float | None) -> str:
    return "—" if x is None or (isinstance(x, float) and math.isnan(x)) else f"{x:.1f}"


def _table(headers: list[str], rows: list[list[str]]) -> str:
    if not rows:
        return "_No data yet._"
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(r) + " |" for r in rows]
    return "\n".join(out)


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8", newline="\n")
        return
    # Rows can differ in their columns (A6 rows add exfil_link_rate), so the header is
    # the union of every row's keys in first-seen order; missing cells stay empty.
    fieldnames = list(dict.fromkeys(k for row in rows for k in row))
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fieldnames, restval="", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


# ------------------------------------------------------------------------------ report
class Reporter:
    def __init__(self, root: Path | None = None) -> None:
        self.root = root or hp.root()
        self.runs = metrics.load_runs(self.root)
        self.data = metrics.collect(self.runs)
        self.out = hp.summary(self.root)
        self.models = sorted({k[0] for k in self.data})

    def records(self, model: str, preset: str, suite: str) -> list[dict[str, Any]]:
        return self.data.get((model, preset, suite), [])

    # --- tables -------------------------------------------------------------
    def asr_rows(self, suite: str = "dev") -> list[dict[str, Any]]:
        rows = []
        for (model, preset, s), recs in sorted(self.data.items()):
            if s != suite:
                continue
            base = self.records(model, "baseline", suite)
            for cat in CATEGORIES:
                row = metrics.category_row(recs, cat)
                if row["trials"] == 0:
                    continue
                p = float("nan")
                label = ""
                if preset != "baseline" and base:
                    bc, dc = metrics.cases_of(base, cat), metrics.cases_of(recs, cat)
                    p = stats.signflip_exact(stats.paired_diffs(bc, dc)) if bc and dc else float("nan")
                    label = stats.attack_label(bc, dc)[0] if bc and dc else ""
                rows.append({"model": model, "suite": suite, "preset": preset, **row,
                             "p_vs_baseline": p, "label_vs_baseline": label})
        return rows

    def benign_rows(self) -> list[dict[str, Any]]:
        rows = []
        for (model, preset, s), recs in sorted(self.data.items()):
            if s != "benign":
                continue
            b = metrics.benign_summary(recs)
            if not b.get("trials"):
                continue
            lat = metrics.latency_summary(recs)
            rows.append({"model": model, "preset": preset, "trials": b["trials"], "accuracy": b["accuracy"],
                         "accuracy_ci_lo": b["accuracy_ci"][0], "accuracy_ci_hi": b["accuracy_ci"][1],
                         "false_refusal_rate": b["false_refusal_rate"], "near_miss_accuracy": b["near_miss_accuracy"],
                         "near_miss_refusal_rate": b["near_miss_refusal_rate"],
                         "safety_any": b["safety"]["any"], "unasked_email": b["safety"]["unasked_email"],
                         "email_to_other": b["safety"]["email_to_other"],
                         "unauthorized_canary": b["safety"]["unauthorized_canary"],
                         "pipeline_failures": b["pipeline_failures"],
                         "latency_median": lat.get("median"), "latency_p95": lat.get("p95")})
        return rows

    def a7_rows(self) -> list[dict[str, Any]]:
        rows = []
        for (model, preset, s), recs in sorted(self.data.items()):
            if s != "dev":
                continue
            a7 = [r for r in recs if r.get("category") == "tool_misuse"]
            if not a7:
                continue
            n = len(a7)
            conds: dict[str, int] = {"recipient": 0, "canary": 0, "attacker_link": 0}
            for r in a7:
                for c in ((r.get("check_result") or {}).get("detail") or {}).get("conditions", []):
                    conds[c] = conds.get(c, 0) + 1
            rows.append({"model": model, "preset": preset, "trials": n,
                         "asr_click_through": sum(1 for r in a7 if r.get("success")) / n,
                         "asr_vigilant": sum(1 for r in a7 if r.get("success_vigilant")) / n,
                         **{f"cond_{k}": v for k, v in conds.items()}})
        return rows

    def style_rows(self) -> list[dict[str, Any]]:
        rows = []
        for (model, preset, s), recs in sorted(self.data.items()):
            if s != "dev":
                continue
            for cat in ("indirect_phishing", "markdown_exfil", "tool_misuse"):
                for style in ("explicit_override", "implicit"):
                    sub = [r for r in recs if r.get("category") == cat and r.get("injection_style") == style]
                    if sub:
                        rows.append({"model": model, "preset": preset, "category": cat, "style": style,
                                     "trials": len(sub), "asr": sum(1 for r in sub if r.get("success")) / len(sub)})
            a6 = [r for r in recs if r.get("category") == "markdown_exfil"]
            for sub_t in sorted({str(r.get("subtype")) for r in a6}):
                sub = [r for r in a6 if str(r.get("subtype")) == sub_t]
                rows.append({"model": model, "preset": preset, "category": "markdown_exfil", "style": f"payload:{sub_t}",
                             "trials": len(sub), "asr": sum(1 for r in sub if r.get("success")) / len(sub),
                             "exfil_link_rate": sum(1 for r in sub if r.get("exfil_link")) / len(sub)})
        return rows

    def retrieved_poison_rows(self) -> list[dict[str, Any]]:
        rows = []
        for model in self.models:
            base = self.records(model, "baseline", "dev")
            in_top4 = {str(r["case_id"]) for r in base if (r.get("diagnostics") or {}).get("poison_in_top4")}
            for (m, preset, s), recs in sorted(self.data.items()):
                if m != model or s != "dev":
                    continue
                for cat in ("indirect_phishing", "retrieval_hijack", "markdown_exfil", "tool_misuse"):
                    all_c = [r for r in recs if r.get("category") == cat]
                    ret_c = [r for r in all_c if str(r["case_id"]) in in_top4]
                    if not all_c:
                        continue
                    rows.append({"model": model, "preset": preset, "category": cat,
                                 "asr": sum(1 for r in all_c if r.get("success")) / len(all_c),
                                 "retrieved_poison_cases": len({str(r["case_id"]) for r in ret_c}),
                                 "retrieved_poison_asr": (sum(1 for r in ret_c if r.get("success")) / len(ret_c))
                                 if ret_c else float("nan"),
                                 "quarantine_rate": sum(1 for r in all_c if (r.get("diagnostics") or {}).get("quarantined"))
                                 / len(all_c)})
        return rows

    def pooled_rows(self, suite: str) -> list[dict[str, Any]]:
        rows = []
        for model in self.models:
            base = self.records(model, "baseline", suite)
            for preset in ["all", *ABLATION_PRESETS, *SINGLE_PRESETS[:-1]]:
                recs = self.records(model, preset, suite)
                if not base or not recs:
                    continue
                bc = metrics.cases_of(base)
                dc = metrics.cases_of(recs)
                d, lo, hi = stats.paired_bootstrap_diff_ci(bc, dc)
                p = stats.signflip_random(stats.paired_diffs(bc, dc))
                rows.append({"model": model, "suite": suite, "preset": preset, "baseline_asr": stats.asr(bc),
                             "preset_asr": stats.asr(dc), "diff": d, "diff_ci_lo": lo, "diff_ci_hi": hi,
                             "p_signflip": p, "cases": len(set(bc) & set(dc))})
        return rows

    def ablation_rows(self) -> list[dict[str, Any]]:
        rows = []
        for model in self.models:
            full = self.records(model, "all", "dev")
            if not full:
                continue
            for preset in ABLATION_PRESETS:
                recs = self.records(model, preset, "dev")
                if not recs:
                    continue
                for cat in CATEGORIES:
                    fc, ac = metrics.cases_of(full, cat), metrics.cases_of(recs, cat)
                    if not fc or not ac:
                        continue
                    rows.append({"model": model, "preset": preset, "category": cat,
                                 "all_asr": stats.asr(fc), "ablated_asr": stats.asr(ac),
                                 "p_signflip": stats.signflip_exact(stats.paired_diffs(fc, ac))})
        return rows

    def latency_rows(self, suite: str = "benign") -> list[dict[str, Any]]:
        """Virtual latency per preset, its overhead over baseline, and its mean split by stage."""
        rows = []
        for model, preset, _s in _keys(self.data, [suite]):
            recs = [r for r in self.records(model, preset, suite)
                    if (r.get("diagnostics") or {}).get("virtual_latency_seconds") is not None]
            lat = metrics.latency_summary(recs)
            if not lat.get("n"):
                continue
            base = metrics.latency_summary(self.records(model, "baseline", suite))
            parts = [stage_split(r) for r in recs]
            rows.append({"model": model, "suite": suite, "preset": preset, "trials": lat["n"],
                         "median": lat["median"], "p95": lat["p95"], "mean": lat["total_seconds"] / lat["n"],
                         "overhead_median": (lat["median"] - base["median"]) if base.get("n") else float("nan"),
                         **{f"mean_{k}": sum(p[k] for p in parts) / len(parts) for k in STAGES}})
        return rows

    def resource_rows(self) -> list[dict[str, Any]]:
        """Resources per trial and the generation-cache hit rate, per model, suite, and preset."""
        return [{"model": m, "suite": s, "preset": p, "trials": len(self.records(m, p, s)),
                 **metrics.resources_summary(self.records(m, p, s))} for m, p, s in _keys(self.data, SUITE_ORDER)]

    def compute_rows(self) -> list[dict[str, Any]]:
        """Wall-clock compute time of every recorded run (there is no dollar cost)."""
        rows = []
        for run in sorted(self.runs, key=lambda r: str(r.meta.get("started_at", ""))):
            m = run.meta
            try:
                minutes = (datetime.fromisoformat(str(m["ended_at"]))
                           - datetime.fromisoformat(str(m["started_at"]))).total_seconds() / 60
            except (KeyError, ValueError):
                minutes = float("nan")
            rows.append({"run_id": m.get("run_id"), "model": m.get("model"), "preset": m.get("preset"),
                         "suites": "+".join(str(s) for s in m.get("suites") or []),
                         "trials": int(m.get("trials_recorded") or len(run.records)), "minutes": minutes,
                         "cache_hit_rate": m.get("cache_hit_rate")})
        return rows

    def a5_rows(self) -> list[dict[str, Any]]:
        """A5 strict (the primary metric) next to loose (§8.1)."""
        rows = []
        for model, preset, suite in _keys(self.data, ["dev", "heldout", "adaptive"]):
            a5 = [r for r in self.records(model, preset, suite) if r.get("category") == "retrieval_hijack"]
            if a5:
                rows.append({"model": model, "suite": suite, "preset": preset, "trials": len(a5),
                             "strict_asr": sum(1 for r in a5 if r.get("success")) / len(a5),
                             "loose_asr": sum(1 for r in a5 if r.get("a5_loose")) / len(a5)})
        return rows

    def adaptive_budget_rows(self) -> list[dict[str, Any]]:
        """Development attempts used per category (Model A, preset all), from the attempt log."""
        from ragsec.harness import adaptive
        from ragsec.harness.data import load_case_file

        log = adaptive.load_log(self.root)
        final_file = adaptive.final_path(self.root)
        final = Counter(str(c["category"]) for c in load_case_file(final_file)) if final_file.is_file() else Counter()
        rows = []
        for cat in CATEGORIES:
            entries = [e for e in log if e["category"] == cat]
            rows.append({"category": cat, "code": CATEGORY_CODE[cat], "attempts": len(entries),
                         "budget": adaptive.BUDGET_PER_CATEGORY, "dev_trials": sum(int(e["trials"]) for e in entries),
                         "dev_successes": sum(int(e["successes"]) for e in entries),
                         "best_attempt": max((int(e["successes"]) for e in entries), default=None),
                         "final_cases": final[cat]})
        return rows

    def adaptive_rows(self) -> list[dict[str, Any]]:
        """Final adaptive set per model, source, and category, next to the frozen dev set's ASR."""
        rows = []
        for model, preset, _s in _keys(self.data, ["adaptive"]):
            recs = self.records(model, preset, "adaptive")
            static = self.records(model, preset, "dev")
            for source in sorted({str(r.get("source")) for r in recs}):
                sub = [r for r in recs if str(r.get("source")) == source]
                for cat in CATEGORIES:
                    row = metrics.category_row(sub, cat)
                    if not row["trials"]:
                        continue
                    st = metrics.category_row(static, cat)
                    rows.append({"model": model, "preset": preset, "source": source, **row,
                                 "static_dev_asr": st["asr"] if st["trials"] else float("nan")})
        return rows

    # --- predictions ---------------------------------------------------------
    def score_predictions(self, pred: predictions.Predictions) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        real: list[dict[str, Any]] = []
        by_design: list[dict[str, Any]] = []
        for model in self.models:
            base_dev = self.records(model, "baseline", "dev")
            base_ben = self.records(model, "baseline", "benign")
            if not base_dev:
                continue
            for row in predictions.ATTACK_ROWS:
                preset = predictions.PRESET_FOR_ROW[row]
                recs = self.records(model, preset, "dev")
                if not recs:
                    continue
                for i, cat in enumerate(CATEGORIES):
                    col = f"A{i + 1}"
                    bc, dc = metrics.cases_of(base_dev, cat), metrics.cases_of(recs, cat)
                    result, info = stats.attack_label(bc, dc)
                    predicted = pred.attack.get((row, col))
                    entry = {"model": model, "row": row, "col": col, "predicted": predicted, "result": result,
                             "correct": None if (predicted is None or result in ("inconclusive", "not measurable"))
                             else predicted == result, "info": info}
                    (by_design if (row, col) in predictions.BY_DESIGN_CELLS else real).append(entry)
                    if (row, col) in predictions.BY_DESIGN_VIGILANT:
                        vb = metrics.cases_of(base_dev, cat, "success_vigilant")
                        vd = metrics.cases_of(recs, cat, "success_vigilant")
                        vres, vinfo = stats.attack_label(vb, vd)
                        by_design.append({"model": model, "row": row, "col": f"{col} (vigilant)",
                                          "predicted": "stops", "result": vres,
                                          "correct": None if vres in ("inconclusive", "not measurable")
                                          else vres == "stops", "info": vinfo})
                ben = self.records(model, preset, "benign")
                if base_ben and ben:
                    bb = [r for r in base_ben if r.get("benign")]
                    db = [r for r in ben if r.get("benign")]
                    acc = stats.accuracy_band(sum(r["benign"]["accurate"] for r in bb), len(bb),
                                              sum(r["benign"]["accurate"] for r in db), len(db))
                    ref = stats.refusal_band(sum(r["benign"]["refusal"] for r in bb), len(bb),
                                             sum(r["benign"]["refusal"] for r in db), len(db))
                    for col, res in ((predictions.BENIGN_COL, acc), (predictions.REFUSAL_COL, ref)):
                        p = pred.attack.get((row, col))
                        real.append({"model": model, "row": row, "col": col, "predicted": p, "result": res,
                                     "correct": None if p is None else p == res, "info": {}})
        return real, by_design

    # --- load test (extension, §8.8) -------------------------------------------
    def load_rows(self) -> list[dict[str, Any]]:
        """Normal users and attackers per (preset, condition), from the latest complete,
        non-smoke run of each (results/raw/load/)."""
        from ragsec.harness import load as ld

        runs = ld.latest_runs(self.root)
        keys = sorted(runs, key=lambda k: (LOAD_PRESETS.index(k[0]) if k[0] in LOAD_PRESETS else len(LOAD_PRESETS),
                                           _order(k[0]), k[0], k[1]))
        rows = []
        for preset, attack in keys:
            run = runs[(preset, attack)]
            meta = run["meta"]
            s = ld.summarize(run["normal"], run["attackers"])
            statuses = " ".join(f"{k}:{v}" for k, v in s.pop("normal_statuses").items())
            rows.append({"preset": preset, "attack": attack, "run_id": meta["run_id"],
                         "window_minutes": meta.get("window_minutes"), "rate_per_minute": meta.get("rate_per_minute"),
                         **s, "normal_statuses": statuses,
                         "attacker_admitted": s["attacker_requests"] - s["attacker_rejected_by_d7"],
                         "wall_minutes": round(float(meta.get("wall_seconds", 0.0)) / 60.0, 2)})
        return rows

    def load_dos_rows(self, rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """§8.8's verdict for every preset measured both with and without the attack."""
        from ragsec.harness import load as ld
        from ragsec.harness.data import read_yaml

        cfg = read_yaml(hp.harness_config(self.root))["load"]
        by_key = {(r["preset"], r["attack"]): r for r in rows}
        out = []
        for preset in dict.fromkeys(r["preset"] for r in rows):
            if (preset, False) in by_key and (preset, True) in by_key:
                v = ld.dos_verdict(by_key[(preset, False)], by_key[(preset, True)],
                                   p95_multiplier=float(cfg["dos_p95_multiplier"]),
                                   error_rate=float(cfg["dos_error_rate"]))
                out.append({"preset": preset, **v})
        return out

    def _load_section(self, rows: list[dict[str, Any]], dos: list[dict[str, Any]]) -> str:
        if not rows:
            return "_Not run yet._"
        cap_path = self.out / "load_capacity.json"
        cap = json.loads(cap_path.read_text(encoding="utf-8")) if cap_path.is_file() else {}
        first = rows[0]
        parts = []
        if cap:
            parts.append(f"Capacity C = {cap['capacity_per_minute']:.2f} completed requests per minute (`baseline`, "
                         f"one client sending back to back for {cap['elapsed_seconds'] / 60:.1f} minutes, "
                         f"{cap['completed']} answers). Normal users ask at 50% of C = "
                         f"{first['rate_per_minute']:.2f} requests per minute for {first['window_minutes']:g} "
                         f"minutes, on the same schedule in every run "
                         f"({first['normal_requests']} requests).")
        parts += ["", "**Normal users** (latency from each request's scheduled time, over completed requests):", "",
                  _table(["Preset", "Attack", "Requests", "Completed", "Error rate", "Statuses", "Median (s)",
                          "p95 (s)", "Max (s)"],
                         [[r["preset"], "yes" if r["attack"] else "no", str(r["normal_requests"]),
                           str(r["normal_completed"]), _fmt(r["normal_error_rate"]), r["normal_statuses"],
                           _secs(r["median_latency"]), _secs(r["p95_latency"]), _secs(r["max_latency"])]
                          for r in rows]),
                  "", "**Denial of service** (§8.8: with the attack, p95 latency more than doubles or the error rate "
                  "exceeds 5%):", "",
                  _table(["Preset", "p95 without → with (s)", "Ratio", "Error rate without → with", "DoS"],
                         [[d["preset"], f"{_secs(d['p95_without'])} → {_secs(d['p95_with'])}",
                           "—" if d["p95_ratio"] is None else f"{d['p95_ratio']:.1f}×",
                           f"{_fmt(d['error_rate_without'])} → {_fmt(d['error_rate_with'])}",
                           ("**yes**" if d["dos"] else "no") + (" (latency)" if d["latency_rule"] else "")
                           + (" (errors)" if d["error_rule"] else "")] for d in dos]),
                  "", "**Attackers** (2 users × 4 requests in flight; a worker pauses 1 s after an immediate "
                  "rejection, so the rejected count depends on that pause):", "",
                  _table(["Preset", "Requests", "Admitted", "Served (of which D5 refused)",
                          "Rejected by D7 (413/429)", "Timed out by D7 (504)", "Cancelled at the end", "Other"],
                         [[r["preset"], str(r["attacker_requests"]), str(r["attacker_admitted"]),
                           f"{r['attacker_served']} ({r['attacker_refused_by_d5']})", str(r["attacker_rejected_by_d7"]),
                           str(r["attacker_timed_out_by_d7"]), str(r["attacker_cancelled_at_end"]),
                           str(r["attacker_other"])] for r in rows if r["attack"]])]
        return "\n".join(parts)

    def load_chart(self, rows: list[dict[str, Any]]) -> list[str]:
        """13. Load test: normal users' p95 latency and error rate, with and without the attack."""
        presets = list(dict.fromkeys(r["preset"] for r in rows))
        if not presets:
            return []
        plt = self._pyplot()
        self.out.mkdir(parents=True, exist_ok=True)
        by_key = {(r["preset"], r["attack"]): r for r in rows}
        fig, axes = plt.subplots(1, 2, figsize=(8.2, 0.9 + 0.5 * len(presets)), sharey=True)
        panels = (("p95_latency", "p95 latency (s, log scale)"), ("normal_error_rate", "error rate"))
        for ax, (field, label) in zip(axes, panels, strict=True):
            for y, p in enumerate(presets):
                pair = [by_key.get((p, a)) for a in (False, True)]
                vals: list[float | None] = [None if r is None else r[field] for r in pair]
                ys: list[float] = [float(y), float(y)]
                v0, v1 = vals
                if v0 is not None and v1 is not None:
                    if abs(v0 - v1) < 1e-9:  # equal values: offset, so neither dot hides the other
                        ys = [y - 0.13, y + 0.13]
                    else:
                        ax.plot([v0, v1], ys, color=AXIS, linewidth=2, zorder=1)
                for k, (v, color) in enumerate(zip(vals, SERIES, strict=True)):
                    if v is None:
                        continue
                    ax.scatter([v], [ys[k]], s=55, color=color, edgecolors=SURFACE, linewidths=1.5, zorder=2,
                               label=("without the attack", "with the attack")[k] if y == 0 else None)
                    if k == 1:
                        text = f"{v:.0f} s" if field == "p95_latency" else f"{100 * v:.0f}%"
                        ax.annotate(text, (v, ys[k]), xytext=(7, 0), textcoords="offset points", va="center",
                                    color=INK2, fontsize=7)
            values = [r[field] for r in rows if r[field] is not None]
            if field == "p95_latency":
                from matplotlib.ticker import NullFormatter

                lo, hi = (min(values) / 1.4, max(values) * 1.4) if values else (1.0, 100.0)
                ax.set_xscale("log")
                ax.set_xlim(lo, hi)
                ax.set_xticks([t for t in (1, 2, 5, 10, 20, 50, 100, 200, 500, 1000) if lo <= t <= hi])
                ax.xaxis.set_major_formatter(lambda v, _p: f"{v:g}")
                ax.xaxis.set_minor_formatter(NullFormatter())
            else:
                top = max([0.1, *(1.3 * v for v in values)])
                ax.set_xlim(-0.03 * top, top)
                ax.axvline(0.05, color=MUTED, linewidth=0.8, linestyle="--", zorder=0)
                ax.xaxis.set_major_formatter(lambda v, _p: f"{100 * v:.0f}%")
            ax.set_xlabel(label)
            ax.grid(axis="x")
            ax.set_axisbelow(True)
            ax.tick_params(axis="y", length=0)
        axes[0].set_yticks(range(len(presets)), presets)
        axes[0].set_ylim(len(presets) - 0.4, -0.7)
        axes[0].legend(loc="lower right", fontsize=7)
        fig.suptitle("Load test, Model A: normal users with and without two attackers (dashed line: 5%)",
                     fontsize=9, color=INK)
        return [self._save(plt, fig, "load_latency.png")]

    # --- charts --------------------------------------------------------------
    @staticmethod
    def _pyplot() -> Any:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        plt.rcParams.update({
            "font.family": "sans-serif", "font.size": 8, "text.color": INK, "axes.titlecolor": INK,
            "axes.labelcolor": INK2, "axes.edgecolor": AXIS, "xtick.color": INK2, "ytick.color": INK2,
            "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
            "axes.spines.top": False, "axes.spines.right": False, "grid.color": GRID, "grid.linewidth": 0.6,
            "legend.frameon": False})
        return plt

    def _save(self, plt: Any, fig: Any, name: str) -> str:
        fig.tight_layout()
        fig.savefig(self.out / name, dpi=130)
        plt.close(fig)
        return name

    def charts(self, asr: list[dict[str, Any]], benign: list[dict[str, Any]], latency: list[dict[str, Any]],
               heldout: list[dict[str, Any]], ablation: list[dict[str, Any]],
               adaptive: list[dict[str, Any]]) -> dict[str, list[str]]:
        """Charts by report section; each one has a table twin in the same section."""
        from matplotlib.colors import LinearSegmentedColormap, TwoSlopeNorm

        plt = self._pyplot()
        self.out.mkdir(parents=True, exist_ok=True)
        made: dict[str, list[str]] = {"charts": [], "charts-ablation": [], "charts-adaptive": []}
        seq = LinearSegmentedColormap.from_list("seq_blue", SEQ_BLUE)
        div = LinearSegmentedColormap.from_list("blue_gray_red", DIVERGING)

        for model in self.models:  # 1. ASR heatmap, category x preset
            presets = [p for p in PRESET_ORDER if any(r["preset"] == p and r["model"] == model for r in asr)]
            if not presets:
                continue
            grid = [[next((r["asr"] for r in asr if r["model"] == model and r["preset"] == p
                           and r["category"] == c), float("nan")) for p in presets] for c in CATEGORIES]
            fig, ax = plt.subplots(figsize=(1.4 + 0.55 * len(presets), 4.0))
            im = ax.imshow(grid, vmin=0, vmax=1, cmap=seq, aspect="auto")
            ax.set_xticks(range(len(presets)), presets, rotation=60, ha="right")
            ax.set_yticks(range(len(CATEGORIES)), [CATEGORY_CODE[c] for c in CATEGORIES])
            for yi, row in enumerate(grid):
                for xi, v in enumerate(row):
                    if not math.isnan(v):
                        ax.text(xi, yi, f"{100 * v:.0f}", ha="center", va="center", fontsize=7,
                                color="#ffffff" if v >= 0.55 else INK)
            ax.spines[:].set_visible(False)
            ax.tick_params(length=0)
            ax.set_title(f"Attack success rate (%), dev set, model {model}")
            cb = fig.colorbar(im, ax=ax, fraction=0.03)
            cb.outline.set_visible(False)
            cb.ax.yaxis.set_major_formatter(lambda v, _p: f"{100 * v:.0f}%")
            made["charts"].append(self._save(plt, fig, f"asr_heatmap_{model}.png"))

        if benign:  # 3. benign accuracy and false refusals
            rows = sorted(benign, key=lambda r: (r["model"], _order(r["preset"])))
            fig, ax = plt.subplots(figsize=(8, 3.4))
            xs = list(range(len(rows)))
            ax.bar([x - 0.2 for x in xs], [r["accuracy"] for r in rows], width=0.4, color=SERIES[0],
                   edgecolor=SURFACE, linewidth=1, label="benign accuracy")
            ax.bar([x + 0.2 for x in xs], [r["false_refusal_rate"] for r in rows], width=0.4, color=SERIES[1],
                   edgecolor=SURFACE, linewidth=1, label="false refusals")
            ax.set_xticks(xs, [f"{r['model']}:{r['preset']}" for r in rows], rotation=60, ha="right")
            ax.set_ylim(0, 1)
            ax.yaxis.set_major_formatter(lambda v, _p: f"{100 * v:.0f}%")
            ax.grid(axis="y")
            ax.set_axisbelow(True)
            ax.legend(loc="upper right", ncols=2)
            ax.set_title("Benign accuracy and false refusals by preset")
            made["charts"].append(self._save(plt, fig, "benign_by_preset.png"))

        lat_models = sorted({r["model"] for r in latency})
        if lat_models:  # 7. latency overhead by preset
            heights = [sum(1 for r in latency if r["model"] == m) for m in lat_models]
            fig, axes = plt.subplots(len(lat_models), 1, figsize=(6.4, 0.9 + 0.24 * sum(heights) + 0.5 * len(lat_models)),
                                     gridspec_kw={"height_ratios": heights}, squeeze=False)
            top = max(r["p95"] for r in latency) * 1.15
            for ax, m in zip(axes[:, 0], lat_models, strict=True):
                rows = [r for r in latency if r["model"] == m][::-1]
                ys = list(range(len(rows)))
                ax.barh(ys, [r["median"] for r in rows], height=0.55, color=SERIES[0], label="median")
                ax.scatter([r["p95"] for r in rows], ys, marker="|", s=90, color=INK2, linewidths=1.5, label="p95")
                base = next((r["median"] for r in rows if r["preset"] == "baseline"), None)
                if base is not None:
                    ax.axvline(base, color=MUTED, linewidth=0.8, zorder=0)
                ax.set_yticks(ys, [r["preset"] for r in rows])
                ax.set_xlim(0, top)
                ax.grid(axis="x")
                ax.set_axisbelow(True)
                ax.tick_params(axis="y", length=0)
                ax.set_title(f"Model {m}", loc="left", fontsize=8)
            axes[-1, 0].set_xlabel("virtual latency per benign question (s); gray line = baseline median")
            axes[0, 0].legend(loc="upper right", ncols=2)
            fig.suptitle("Latency by preset, benign set", fontsize=9, color=INK)
            made["charts"].append(self._save(plt, fig, "latency_by_preset.png"))

        held = [r for r in heldout if r["preset"] == "all"]
        if held:  # 8. held-out baseline versus all, pooled
            fig, ax = plt.subplots(figsize=(6.4, 0.9 + 0.55 * len(held)))
            for y, r in enumerate(held):
                ax.plot([r["preset_asr"], r["baseline_asr"]], [y, y], color=AXIS, linewidth=2, zorder=1)
                ax.scatter([r["baseline_asr"]], [y], s=55, color=SERIES[0], edgecolors=SURFACE, linewidths=1.5,
                           zorder=2, label="baseline" if y == 0 else None)
                ax.scatter([r["preset_asr"]], [y], s=55, color=SERIES[1], edgecolors=SURFACE, linewidths=1.5,
                           zorder=2, label="all" if y == 0 else None)
                ax.annotate(f"{100 * r['diff']:+.1f} pp (95% CI {100 * r['diff_ci_lo']:+.1f} to "
                            f"{100 * r['diff_ci_hi']:+.1f}), p = {r['p_signflip']:.4f}",
                            (r["baseline_asr"], y), xytext=(10, 0), textcoords="offset points", va="center",
                            color=INK2, fontsize=7)
            ax.set_yticks(range(len(held)), [f"Model {r['model']} ({r['cases']} cases)" for r in held])
            ax.set_ylim(-0.6, len(held) - 0.4)
            ax.set_xlim(0, 1)
            ax.xaxis.set_major_formatter(lambda v, _p: f"{100 * v:.0f}%")
            ax.grid(axis="x")
            ax.set_axisbelow(True)
            ax.tick_params(axis="y", length=0)
            ax.legend(loc="lower right", ncols=2)
            ax.set_title("Held-out set, pooled across categories: ASR at baseline and under all")
            made["charts"].append(self._save(plt, fig, "heldout_pooled.png"))

        for model in sorted({r["model"] for r in ablation}):  # 2. ablation
            presets = [p for p in ABLATION_PRESETS if any(r["model"] == model and r["preset"] == p for r in ablation)]
            cell = {(r["preset"], r["category"]): r for r in ablation if r["model"] == model}
            grid = [[(cell[(p, c)]["ablated_asr"] - cell[(p, c)]["all_asr"]) if (p, c) in cell else float("nan")
                     for p in presets] for c in CATEGORIES]
            span = max([0.1, *(abs(v) for row in grid for v in row if not math.isnan(v))])
            fig, ax = plt.subplots(figsize=(1.6 + 0.62 * len(presets), 4.0))
            im = ax.imshow(grid, cmap=div, norm=TwoSlopeNorm(0.0, -span, span), aspect="auto")
            for yi, c in enumerate(CATEGORIES):
                for xi, p in enumerate(presets):
                    v = grid[yi][xi]
                    if not math.isnan(v) and round(100 * v) != 0:
                        star = "*" if cell[(p, c)]["p_signflip"] < 0.05 else ""
                        ax.text(xi, yi, f"{100 * v:+.0f}{star}", ha="center", va="center", fontsize=7,
                                color="#ffffff" if abs(v) >= 0.6 * span else INK)
            ax.set_xticks(range(len(presets)), [p.replace("all_minus_", "−") for p in presets])
            ax.set_yticks(range(len(CATEGORIES)), [CATEGORY_CODE[c] for c in CATEGORIES])
            ax.spines[:].set_visible(False)
            ax.tick_params(length=0)
            ax.set_xlabel("defense removed from all")
            ax.set_title(f"Ablation, model {model}: change in ASR without one defense (pp; * p < 0.05)")
            cb = fig.colorbar(im, ax=ax, fraction=0.03)
            cb.outline.set_visible(False)
            cb.ax.yaxis.set_major_formatter(lambda v, _p: f"{100 * v:+.0f} pp")
            made["charts-ablation"].append(self._save(plt, fig, f"ablation_{model}.png"))

        ad_all = [r for r in adaptive if r["source"] == "adaptive" and r["preset"] == "all"]
        ad_models = sorted({r["model"] for r in ad_all})
        if ad_models:  # 9. adaptive results against the frozen dev set
            cats = [c for c in CATEGORIES if any(r["category"] == c for r in ad_all)]
            fig, axes = plt.subplots(1, len(ad_models), figsize=(3.4 * len(ad_models), 0.9 + 0.42 * len(cats)),
                                     sharey=True, squeeze=False)
            for ax, m in zip(axes[0], ad_models, strict=True):
                by_cat = {r["category"]: r for r in ad_all if r["model"] == m}
                labeled = False
                for y, c in enumerate(cats):  # two offset rows per category, so equal values never hide
                    found = by_cat.get(c)
                    if found is None:
                        continue
                    ax.scatter([found["static_dev_asr"]], [y - 0.14], s=50, color=SERIES[0], edgecolors=SURFACE,
                               linewidths=1.5, zorder=2, label=None if labeled else "frozen dev set")
                    ax.scatter([found["asr"]], [y + 0.14], s=50, color=SERIES[1], edgecolors=SURFACE,
                               linewidths=1.5, zorder=2, label=None if labeled else "adaptive final set")
                    labeled = True
                ax.set_yticks(range(len(cats)), [CATEGORY_CODE[c] for c in cats])
                ax.set_ylim(len(cats) - 0.4, -0.6)
                ax.set_xlim(0, 1)
                ax.xaxis.set_major_formatter(lambda v, _p: f"{100 * v:.0f}%")
                ax.grid(axis="x")
                ax.set_axisbelow(True)
                ax.tick_params(axis="y", length=0)
                ax.set_title(f"Model {m}, preset all", loc="left", fontsize=8)
            axes[0, -1].legend(loc="lower right", fontsize=7)
            fig.suptitle("ASR under all: frozen dev set versus the adaptive final set", fontsize=9, color=INK)
            made["charts-adaptive"].append(self._save(plt, fig, "adaptive.png"))
        return made

    # --- sections ------------------------------------------------------------
    def build(self, scoring: str | None = None) -> dict[str, str]:
        asr = self.asr_rows("dev")
        benign = self.benign_rows()
        a7 = self.a7_rows()
        styles = self.style_rows()
        poison = self.retrieved_poison_rows()
        ablation = self.ablation_rows()
        heldout = self.pooled_rows("heldout")
        adaptive = self.adaptive_rows()
        budget = self.adaptive_budget_rows()
        latency = self.latency_rows("benign")
        resources = self.resource_rows()
        compute = self.compute_rows()
        a5 = self.a5_rows()
        load = self.load_rows()
        load_dos = self.load_dos_rows(load) if load else []
        for name, rows in (("asr_dev.csv", asr), ("benign.csv", benign), ("a7_policies.csv", a7),
                           ("styles_and_payloads.csv", styles), ("retrieved_poison.csv", poison),
                           ("ablation.csv", ablation), ("heldout_pooled.csv", heldout),
                           ("adaptive.csv", adaptive), ("adaptive_budget.csv", budget),
                           ("latency_benign.csv", latency), ("resources.csv", resources),
                           ("compute_time.csv", compute), ("a5_strict_loose.csv", a5),
                           ("load.csv", load), ("load_dos.csv", load_dos)):
            _write_csv(self.out / name, rows)
        charts = self.charts(asr, benign, latency, heldout, ablation, adaptive)
        charts["charts-load"] = self.load_chart(load)
        sections: dict[str, str] = {}
        sections["summary"] = self._summary(asr, benign, heldout, adaptive, load_dos)
        sections["results-load"] = self._load_section(load, load_dos)
        sections["results-single"] = _table(
            ["Model", "Preset", "Cat.", "Cases", "Trials", "ASR", "95% CI (cluster, approx.)", "≥1 of 3",
             "p vs baseline", "Label"],
            [[r["model"], r["preset"], r["code"], str(r["cases"]), str(r["trials"]), _fmt(r["asr"]),
              f"{_fmt(r['ci_lo'])}–{_fmt(r['ci_hi'])}", _fmt(r["case_any_success_share"]),
              _fmt(r["p_vs_baseline"], pct=False), r["label_vs_baseline"]]
             for r in asr if r["preset"] in ["baseline", *SINGLE_PRESETS]])
        sections["results-ablation"] = _table(
            ["Model", "Preset", "Cat.", "ASR all", "ASR ablated", "p (sign-flip)"],
            [[r["model"], r["preset"], CATEGORY_CODE[r["category"]], _fmt(r["all_asr"]), _fmt(r["ablated_asr"]),
              _fmt(r["p_signflip"], pct=False)] for r in ablation])
        sections["results-benign"] = _table(
            ["Model", "Preset", "Trials", "Accuracy", "95% CI", "False refusals", "Near-miss acc.",
             "Near-miss refusals", "Safety (any)", "Latency median / p95 (s)"],
            [[r["model"], r["preset"], str(r["trials"]), _fmt(r["accuracy"]),
              f"{_fmt(r['accuracy_ci_lo'])}–{_fmt(r['accuracy_ci_hi'])}", _fmt(r["false_refusal_rate"]),
              _fmt(r["near_miss_accuracy"]), _fmt(r["near_miss_refusal_rate"]), _fmt(r["safety_any"]),
              f"{r['latency_median'] or 0:.1f} / {r['latency_p95'] or 0:.1f}"] for r in benign])
        sections["results-a7"] = _table(
            ["Model", "Preset", "Trials", "ASR click-through (primary)", "ASR vigilant", "recipient", "canary",
             "attacker link"],
            [[r["model"], r["preset"], str(r["trials"]), _fmt(r["asr_click_through"]), _fmt(r["asr_vigilant"]),
              str(r["cond_recipient"]), str(r["cond_canary"]), str(r["cond_attacker_link"])] for r in a7])
        sections["results-styles"] = _table(
            ["Model", "Preset", "Category", "Style / payload", "Trials", "ASR", "exfil_link"],
            [[r["model"], r["preset"], r["category"], r["style"], str(r["trials"]), _fmt(r["asr"]),
              _fmt(r.get("exfil_link_rate"))] for r in styles])
        sections["results-retrieved-poison"] = _table(
            ["Model", "Preset", "Category", "ASR", "Cases with poison in baseline top 4", "Retrieved-poison ASR",
             "D6 quarantine rate"],
            [[r["model"], r["preset"], r["category"], _fmt(r["asr"]), str(r["retrieved_poison_cases"]),
              _fmt(r["retrieved_poison_asr"]), _fmt(r["quarantine_rate"])] for r in poison])
        sections["results-heldout"] = _table(
            ["Model", "Preset", "Cases", "Baseline ASR", "Preset ASR", "Difference", "95% CI (paired cluster)",
             "p (sign-flip, 100k)"],
            [[r["model"], r["preset"], str(r["cases"]), _fmt(r["baseline_asr"]), _fmt(r["preset_asr"]),
              _fmt(r["diff"]), f"{_fmt(r['diff_ci_lo'])}–{_fmt(r['diff_ci_hi'])}", _fmt(r["p_signflip"], pct=False)]
             for r in heldout if r["preset"] == "all"])
        sections["results-adaptive"] = self._adaptive_section(budget, adaptive)
        sections["results-a5"] = _table(
            ["Model", "Suite", "Preset", "Trials", "Strict ASR (primary)", "Loose ASR"],
            [[r["model"], r["suite"], r["preset"], str(r["trials"]), _fmt(r["strict_asr"]), _fmt(r["loose_asr"])]
             for r in a5])
        sections["results-latency"] = _table(
            ["Model", "Preset", "Trials", "Median (s)", "p95 (s)", "Median vs baseline (s)", "Mean (s)",
             "model", "retrieval (D1)", "D5", "prompt (D4)", "tool (D3)", "D2"],
            [[r["model"], r["preset"], str(r["trials"]), f"{r['median']:.2f}", f"{r['p95']:.2f}",
              "—" if math.isnan(r["overhead_median"]) else f"{r['overhead_median']:+.2f}", f"{r['mean']:.2f}",
              *(f"{r[f'mean_{k}']:.2f}" for k in STAGES[:-1])] for r in latency])
        sections["results-resources"] = _table(
            ["Model", "Suite", "Preset", "Trials", "Output tokens", "Model calls", "Tool-call attempts",
             "Context overflows", "Server errors", "Cache hit rate"],
            [[r["model"], r["suite"], r["preset"], str(r["trials"]), f"{r['output_tokens_per_trial']:.0f}",
              f"{r['model_calls_per_trial']:.2f}", f"{r['tool_attempts_per_trial']:.2f}", str(r["context_overflows"]),
              str(r["errors"]), _fmt(r["cache_hit_rate"])] for r in resources])
        total_min = sum(r["minutes"] for r in compute if not math.isnan(r["minutes"]))
        sections["results-compute"] = (_table(
            ["Run", "Model", "Preset", "Suites", "Trials", "Wall time (min)", "Cache hit rate"],
            [[str(r["run_id"]), str(r["model"]), str(r["preset"]), r["suites"], str(r["trials"]),
              "—" if math.isnan(r["minutes"]) else f"{r['minutes']:.1f}",
              _fmt(r["cache_hit_rate"]) if isinstance(r["cache_hit_rate"], int | float) else "—"] for r in compute])
            + (f"\n\nTotal: {len(compute)} runs, {sum(r['trials'] for r in compute)} trials, "
               f"{total_min / 60:.1f} hours of wall time." if compute else ""))
        sc = self.out / "supplychain.md"
        sections["results-supplychain"] = sc.read_text(encoding="utf-8") if sc.is_file() else "_Not run yet._"
        au = self.out / "audit.md"
        sections["results-audit"] = au.read_text(encoding="utf-8") if au.is_file() else "_Not run yet._"
        for block, names in charts.items():
            sections[block] = "\n".join(f"![{c}](results/summary/{c})" for c in names) or "_No charts yet._"
        if scoring == "core":
            sections["predictions"] = self._predictions_section()
        return sections

    @staticmethod
    def _adaptive_section(budget: list[dict[str, Any]], adaptive: list[dict[str, Any]]) -> str:
        if not adaptive and not any(b["attempts"] for b in budget):
            return "_No data yet._"
        parts = ["**Development budget** (Model A, preset `all`, 3 trials per attempt, namespace `adaptive-dev`):", "",
                 _table(["Cat.", "Attempts used", "Dev trials", "Dev successes", "Best attempt (of 3)", "Final cases"],
                        [[b["code"], f"{b['attempts']} of {b['budget']}", str(b["dev_trials"]), str(b["dev_successes"]),
                          "—" if b["best_attempt"] is None else str(b["best_attempt"]), str(b["final_cases"])]
                         for b in budget])]
        header = ["Model", "Preset", "Cat.", "Cases", "Trials", "ASR", "95% CI (cluster, approx.)", "≥1 of 3",
                  "Frozen dev ASR (same model and preset)"]

        def rows(rs: list[dict[str, Any]]) -> list[list[str]]:
            return [[r["model"], r["preset"], r["code"], str(r["cases"]), str(r["trials"]), _fmt(r["asr"]),
                     f"{_fmt(r['ci_lo'])}–{_fmt(r['ci_hi'])}", _fmt(r["case_any_success_share"]),
                     _fmt(r["static_dev_asr"])] for r in rs]

        user = [r for r in adaptive if r["source"] == "adaptive_user"]
        other = [r for r in adaptive if r["source"] not in ("adaptive", "adaptive_user")]
        parts += ["", "**Final set** (3 trials, fresh namespace `adaptive-final`). `all` is the result §8.7 asks "
                  "for; `baseline` rows, if any, are a reference run on the same trial keys:", "",
                  _table(header, rows([r for r in adaptive if r["source"] == "adaptive"])), "",
                  "**Owner-written attacks** (`attacks/adaptive/user/`, reported apart and outside the budget): "
                  + ("" if user else "none.")]
        if user:
            parts += ["", _table(header, rows(user))]
        if other:
            parts += ["", "**Other sources:**", "", _table(header, rows(other))]
        return "\n".join(parts)

    def _summary(self, asr: list[dict[str, Any]], benign: list[dict[str, Any]], heldout: list[dict[str, Any]],
                 adaptive: list[dict[str, Any]] | None = None, load_dos: list[dict[str, Any]] | None = None) -> str:
        lines = []
        for model in self.models:
            base = [r for r in asr if r["model"] == model and r["preset"] == "baseline"]
            full = [r for r in asr if r["model"] == model and r["preset"] == "all"]
            if base:
                trials = sum(r["trials"] for r in base)
                succ = sum(r["successes"] for r in base)
                lines.append(f"- Model {model}, baseline, dev: overall ASR {_fmt(succ / trials if trials else None)} "
                             f"over {trials} trials.")
            if full:
                trials = sum(r["trials"] for r in full)
                succ = sum(r["successes"] for r in full)
                lines.append(f"- Model {model}, all defenses, dev: overall ASR {_fmt(succ / trials if trials else None)}.")
            for r in benign:
                if r["model"] == model and r["preset"] in ("baseline", "all"):
                    lines.append(f"- Model {model}, {r['preset']}: benign accuracy {_fmt(r['accuracy'])}, "
                                 f"false refusals {_fmt(r['false_refusal_rate'])}.")
            for r in heldout:
                if r["model"] == model and r["preset"] == "all":
                    lines.append(f"- Model {model}, held-out pooled: baseline {_fmt(r['baseline_asr'])} → all "
                                 f"{_fmt(r['preset_asr'])} (p = {r['p_signflip']:.4f}).")
            ad = [r for r in adaptive or [] if r["model"] == model and r["source"] == "adaptive" and r["preset"] == "all"]
            if ad:
                trials = sum(r["trials"] for r in ad)
                succ = sum(r["successes"] for r in ad)
                cats = {r["category"] for r in ad}
                st = [r for r in full if r["category"] in cats]
                st_trials = sum(r["trials"] for r in st)
                ref = [r for r in adaptive or [] if r["model"] == model and r["source"] == "adaptive"
                       and r["preset"] == "baseline"]
                ref_trials = sum(r["trials"] for r in ref)
                lines.append(f"- Model {model}, adaptive final set under all ({', '.join(r['code'] for r in ad)}): "
                             f"ASR {_fmt(succ / trials if trials else None)} over {trials} trials, against "
                             f"{_fmt(sum(r['successes'] for r in st) / st_trials if st_trials else None)} for the "
                             f"frozen dev set in the same categories"
                             + (f"; the same cases with every defense off: "
                                f"{_fmt(sum(r['successes'] for r in ref) / ref_trials)}." if ref_trials else "."))
        if load_dos:
            lines.append("- Load test (Model A, serve mode, 2 attackers), denial of service by §8.8's rule: " + "; ".join(
                f"{d['preset']} {'yes' if d['dos'] else 'no'} (p95 {_secs(d['p95_without'])} → "
                f"{_secs(d['p95_with'])} s, errors {_fmt(d['error_rate_without'])} → {_fmt(d['error_rate_with'])})"
                for d in load_dos) + ".")
        return "\n".join(lines) or "_No results yet._"

    def _predictions_section(self) -> str:
        md = self.root / "PREDICTIONS.md"
        sha = self.root / "PREDICTIONS.sha256"
        pred = predictions.load_verified(md, sha)  # raises on a hash mismatch
        real, by_design = self.score_predictions(pred)
        _write_csv(self.out / "predictions_real.csv", [{k: v for k, v in r.items() if k != "info"} for r in real])
        _write_csv(self.out / "predictions_by_design.csv",
                   [{k: v for k, v in r.items() if k != "info"} for r in by_design])

        def tally(rows: list[dict[str, Any]]) -> str:
            right = sum(1 for r in rows if r["correct"] is True)
            wrong = sum(1 for r in rows if r["correct"] is False)
            inconclusive = sum(1 for r in rows if r["result"] == "inconclusive")
            unmeasurable = sum(1 for r in rows if r["result"] == "not measurable")
            unpredicted = sum(1 for r in rows if r["predicted"] is None)
            return (f"right {right}, wrong {wrong}, inconclusive {inconclusive}, not measurable {unmeasurable}, "
                    f"unpredicted {unpredicted}")

        parts = ["**Real predictions:** " + tally(real), "", _table(
            ["Model", "Row", "Column", "Predicted", "Result", "Right?"],
            [[r["model"], r["row"], r["col"], str(r["predicted"]), r["result"],
              "—" if r["correct"] is None else ("yes" if r["correct"] else "no")] for r in real]),
            "", "**By-design cells** (a miss is a finding, not a wrong guess): " + tally(by_design), "", _table(
            ["Model", "Row", "Column", "Expected", "Result", "Held?"],
            [[r["model"], r["row"], r["col"], str(r["predicted"]), r["result"],
              "—" if r["correct"] is None else ("yes" if r["correct"] else "no — finding")] for r in by_design])]
        if pred.todo:
            parts += ["", "Unpredicted (TODO) cells: " + ", ".join(pred.todo)]
        notes = self.root / "PREDICTIONS_NOTES.md"
        if notes.is_file():
            parts += ["", "Notes from PREDICTIONS_NOTES.md are shown in that file; they never change a score."]
        return "\n".join(parts)


def run_report(root: Path | None = None, scoring: str | None = None) -> list[str]:
    r = Reporter(root)
    sections = r.build(scoring)
    report = hp.report_md(r.root)
    if not report.is_file():
        raise ReportError("REPORT.md is missing; restore it from git (its user-owned blocks must exist)")
    return update_report_md(report, sections)
