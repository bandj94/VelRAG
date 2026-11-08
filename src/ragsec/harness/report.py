"""``ragsec report`` (spec §15.1, §15.2).

Writes summary CSVs and charts to results/summary/, and refreshes the generated
blocks of REPORT.md (``<!-- GENERATED:BEGIN name -->`` … ``END``). It never touches
the two user-owned blocks: it hashes each before writing and refuses to save if
either changed (tested).
"""

from __future__ import annotations

import csv
import hashlib
import math
import re
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
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
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

    # --- charts --------------------------------------------------------------
    def charts(self, asr: list[dict[str, Any]], benign: list[dict[str, Any]]) -> list[str]:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        made: list[str] = []
        self.out.mkdir(parents=True, exist_ok=True)
        for model in self.models:
            presets = [p for p in ["baseline", *SINGLE_PRESETS, *ABLATION_PRESETS]
                       if any(r["preset"] == p and r["model"] == model for r in asr)]
            if not presets:
                continue
            grid = [[next((r["asr"] for r in asr if r["model"] == model and r["preset"] == p
                           and r["category"] == c), float("nan")) for p in presets] for c in CATEGORIES]
            fig, ax = plt.subplots(figsize=(1.0 + 0.7 * len(presets), 4.8))
            im = ax.imshow(grid, vmin=0, vmax=1, cmap="Reds", aspect="auto")
            ax.set_xticks(range(len(presets)), presets, rotation=60, ha="right")
            ax.set_yticks(range(len(CATEGORIES)), [CATEGORY_CODE[c] for c in CATEGORIES])
            for yi, row in enumerate(grid):
                for xi, v in enumerate(row):
                    if not math.isnan(v):
                        ax.text(xi, yi, f"{100 * v:.0f}", ha="center", va="center", fontsize=7)
            ax.set_title(f"Attack success rate (%), dev set, model {model}")
            fig.colorbar(im, ax=ax, fraction=0.03)
            fig.tight_layout()
            name = f"asr_heatmap_{model}.png"
            fig.savefig(self.out / name, dpi=130)
            plt.close(fig)
            made.append(name)
        if benign:
            fig, ax = plt.subplots(figsize=(8, 3.6))
            labels = [f"{r['model']}:{r['preset']}" for r in benign]
            xs = range(len(benign))
            ax.bar([x - 0.2 for x in xs], [r["accuracy"] for r in benign], width=0.4, label="benign accuracy")
            ax.bar([x + 0.2 for x in xs], [r["false_refusal_rate"] for r in benign], width=0.4, label="false refusals")
            ax.set_xticks(list(xs), labels, rotation=60, ha="right")
            ax.set_ylim(0, 1)
            ax.legend()
            ax.set_title("Benign accuracy and false refusals by preset")
            fig.tight_layout()
            fig.savefig(self.out / "benign_by_preset.png", dpi=130)
            plt.close(fig)
            made.append("benign_by_preset.png")
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
        adaptive = self.asr_rows("adaptive")
        for name, rows in (("asr_dev.csv", asr), ("benign.csv", benign), ("a7_policies.csv", a7),
                           ("styles_and_payloads.csv", styles), ("retrieved_poison.csv", poison),
                           ("ablation.csv", ablation), ("heldout_pooled.csv", heldout),
                           ("adaptive.csv", adaptive)):
            _write_csv(self.out / name, rows)
        charts = self.charts(asr, benign)
        sections: dict[str, str] = {}
        sections["summary"] = self._summary(asr, benign, heldout)
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
        sections["results-adaptive"] = _table(
            ["Model", "Preset", "Cat.", "Cases", "Trials", "ASR"],
            [[r["model"], r["preset"], r["code"], str(r["cases"]), str(r["trials"]), _fmt(r["asr"])] for r in adaptive])
        sc = self.out / "supplychain.md"
        sections["results-supplychain"] = sc.read_text(encoding="utf-8") if sc.is_file() else "_Not run yet._"
        au = self.out / "audit.md"
        sections["results-audit"] = au.read_text(encoding="utf-8") if au.is_file() else "_Not run yet._"
        sections["charts"] = "\n".join(f"![{c}](results/summary/{c})" for c in charts) or "_No charts yet._"
        if scoring == "core":
            sections["predictions"] = self._predictions_section()
        return sections

    def _summary(self, asr: list[dict[str, Any]], benign: list[dict[str, Any]], heldout: list[dict[str, Any]]) -> str:
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
