"""Report tables added in Run 4 (spec §10.3, §15.1): latency by stage, resources, compute
time, A5 strict and loose, and the adaptive round against its budget, on a small fixture."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import pytest
import yaml
from helpers import ROOT

from ragsec.harness import report


def rec(model: str, preset: str, suite: str, case: str, trial: int, *, category: str = "direct_injection",
        success: bool = False, source: str = "claude_seed", model_s: float = 0.8,
        stages: dict[str, float] | None = None, cache_hits: int = 0, **extra: Any) -> dict[str, Any]:
    stages = {"retrieve": 0.1, "d5_message": 0.1} if stages is None else stages
    return {"model": model, "preset": preset, "suite": suite, "case_id": case, "trial": trial, "category": category,
            "success": success, "source": source, "http_status": 200, "scored": True,
            "diagnostics": {"virtual_latency_seconds": model_s + sum(stages.values()), "model_calls": 1,
                            "cache_hits": cache_hits, "output_tokens": 10, "tool_call_attempts": 0,
                            "context_overflow": False,
                            "timings": {"stage_wall_seconds": stages, "model_recorded_seconds": [model_s]}},
            **extra}


def write_run(root: Path, run_id: str, records: list[dict[str, Any]], started: str = "2026-11-10T10:00:00",
              ended: str = "2026-11-10T10:10:00") -> None:
    raw = root / "results" / "raw"
    raw.mkdir(parents=True, exist_ok=True)
    (raw / f"{run_id}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")
    meta = {"run_id": run_id, "model": records[0]["model"], "preset": records[0]["preset"],
            "suites": sorted({r["suite"] for r in records}), "started_at": started, "ended_at": ended,
            "trials_recorded": len(records), "cache_hit_rate": 0.25}
    (raw / f"{run_id}.meta.json").write_text(json.dumps(meta), encoding="utf-8")


def test_stage_split_adds_up_and_covers_every_pipeline_stage() -> None:
    r = rec("A", "all", "benign", "b1", 1, model_s=1.5, stages={"retrieve": 0.2, "d5_chunks": 0.3, "mystery": 0.1})
    parts = report.stage_split(r)
    assert parts["model"] == 1.5 and parts["retrieval"] == 0.2 and parts["D5"] == 0.3 and parts["other"] == 0.1
    assert sum(parts.values()) == pytest.approx(r["diagnostics"]["virtual_latency_seconds"])
    pipeline = (ROOT / "src" / "ragsec" / "app" / "pipeline.py").read_text(encoding="utf-8")
    names = set(re.findall(r"stage\(\"([\w-]+)\"\)", pipeline))
    assert names and names <= set(report.STAGE_OF)  # a new pipeline stage must get a column


@pytest.fixture
def fixture_root(tmp_path: Path) -> Path:
    # Benign latency: baseline 1.0 s per question; all adds 0.5 s of D5 and one cache hit.
    write_run(tmp_path, "base-A", [rec("A", "baseline", "benign", f"b{i}", 1, model_s=0.8) for i in range(4)]
              + [rec("A", "baseline", "dev", f"c{i}", t, success=t == 1) for i in range(4) for t in (1, 2, 3)])
    write_run(tmp_path, "all-A", [rec("A", "all", "benign", f"b{i}", 1, model_s=0.8,
                                      stages={"retrieve": 0.1, "d5_message": 0.6}, cache_hits=i % 2)
                                  for i in range(4)]
              + [rec("A", "all", "dev", f"c{i}", t, success=(i, t) == (0, 1)) for i in range(4) for t in (1, 2, 3)]
              + [rec("A", "all", "dev", "a5", t, category="retrieval_hijack", success=False, a5_loose=t != 3)
                 for t in (1, 2, 3)],
              started="2026-11-10T11:00:00", ended="2026-11-10T11:30:00")
    write_run(tmp_path, "minus-d1-A", [rec("A", "all_minus_d1", "dev", f"c{i}", t, success=t < 3)
                                       for i in range(4) for t in (1, 2, 3)],
              started="2026-11-10T12:00:00", ended="2026-11-10T12:05:00")
    write_run(tmp_path, "adaptive-A", [rec("A", "all", "adaptive", f"A1-P0{i}", t, source="adaptive",
                                           success=(i, t) == (1, 2)) for i in range(1, 4) for t in (1, 2, 3)]
              + [rec("A", "all", "adaptive", "A1-U01", t, source="adaptive_user", success=True) for t in (1, 2, 3)],
              started="2026-11-10T13:00:00", ended="2026-11-10T13:05:00")
    ad = tmp_path / "attacks" / "adaptive"
    ad.mkdir(parents=True)
    log = [{"category": "direct_injection", "attempt": n, "trials": 3, "successes": s, "case_id": f"A1-P0{n}"}
           for n, s in ((1, 0), (2, 1), (3, 0))]
    (ad / "attempts.jsonl").write_text("".join(json.dumps(e) + "\n" for e in log), encoding="utf-8")
    final = [{"id": f"A1-P0{n}", "category": "direct_injection"} for n in (1, 2, 3)]
    (ad / "final.yaml").write_text(yaml.safe_dump(final), encoding="utf-8")
    return tmp_path


def test_latency_overhead_and_stage_means(fixture_root: Path) -> None:
    rows = {r["preset"]: r for r in report.Reporter(fixture_root).latency_rows("benign")}
    assert rows["baseline"]["median"] == pytest.approx(1.0) and rows["all"]["median"] == pytest.approx(1.5)
    assert rows["all"]["overhead_median"] == pytest.approx(0.5) and rows["all"]["mean_D5"] == pytest.approx(0.6)
    assert sum(rows["all"][f"mean_{k}"] for k in report.STAGES) == pytest.approx(rows["all"]["mean"])


def test_resources_compute_time_and_a5_loose(fixture_root: Path) -> None:
    r = report.Reporter(fixture_root)
    res = {(x["suite"], x["preset"]): x for x in r.resource_rows()}
    assert res[("benign", "all")]["cache_hit_rate"] == pytest.approx(0.5)  # 2 hits in 4 model calls
    assert list(res)[0] == ("dev", "baseline")  # ordered by suite, then preset
    minutes = {x["run_id"]: x["minutes"] for x in r.compute_rows()}
    assert minutes["base-A"] == pytest.approx(10.0) and minutes["all-A"] == pytest.approx(30.0)
    (a5,) = r.a5_rows()
    assert a5["strict_asr"] == 0.0 and a5["loose_asr"] == pytest.approx(2 / 3)


def test_adaptive_results_sit_beside_their_budget_with_owner_rows_apart(fixture_root: Path) -> None:
    r = report.Reporter(fixture_root)
    budget = {b["code"]: b for b in r.adaptive_budget_rows()}
    assert budget["A1"]["attempts"] == 3 and budget["A1"]["best_attempt"] == 1 and budget["A1"]["final_cases"] == 3
    assert budget["A2"]["attempts"] == 0 and budget["A2"]["best_attempt"] is None
    rows = {x["source"]: x for x in r.adaptive_rows()}
    assert rows["adaptive"]["trials"] == 9 and rows["adaptive"]["successes"] == 1
    assert rows["adaptive_user"]["successes"] == 3  # reported, never pooled with the budgeted set
    assert rows["adaptive"]["static_dev_asr"] == pytest.approx(1 / 12)
    section = r.build()["results-adaptive"]
    assert "3 of 10" in section and "0 of 10" in section
    owner = section.split("**Owner-written attacks**", 1)[1]
    assert "100.0%" in owner and "100.0%" not in section.split("**Owner-written attacks**", 1)[0]


def test_build_writes_every_chart_and_new_table(fixture_root: Path) -> None:
    sections = report.Reporter(fixture_root).build()
    out = fixture_root / "results" / "summary"
    for name in ("asr_heatmap_A.png", "latency_by_preset.png", "ablation_A.png", "adaptive.png"):
        assert (out / name).stat().st_size > 1000, name
    assert "ablation_A.png" in sections["charts-ablation"] and "adaptive.png" in sections["charts-adaptive"]
    assert "Total: 4 runs" in sections["results-compute"]
    for name in ("results-latency", "results-resources", "results-a5"):
        assert sections[name].startswith("| Model"), name
    assert "adaptive final set under all (A1)" in sections["summary"]
