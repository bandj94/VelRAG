"""Telemetry, the load-test schedule, and the poisoning data builder (spec §14)."""

from __future__ import annotations

import asyncio
import os
import shutil
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from helpers import ROOT
from typer.testing import CliRunner

from ragsec import envsetup
from ragsec.cli import app
from ragsec.harness import load, poison
from ragsec.harness.data import load_facts, read_yaml


def test_cli_sets_telemetry_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in [*envsetup.TELEMETRY_ENV, "HF_HUB_OFFLINE"]:
        monkeypatch.delenv(k, raising=False)
    result = CliRunner().invoke(app, ["corpus", "lint"])
    assert result.exit_code == 0, result.output
    assert os.environ["ANONYMIZED_TELEMETRY"] == "False"
    assert os.environ["HF_HUB_DISABLE_TELEMETRY"] == "1"
    assert os.environ["HF_HUB_OFFLINE"] == "1"
    assert os.environ["PROMPTFOO_DISABLE_TELEMETRY"] == "1"
    assert os.environ["PROMPTFOO_DISABLE_UPDATE"] == "1"


def test_online_context_restores_offline() -> None:
    os.environ["HF_HUB_OFFLINE"] = "1"
    with envsetup.online("test"):
        assert "HF_HUB_OFFLINE" not in os.environ
    assert os.environ["HF_HUB_OFFLINE"] == "1"


# ------------------------------------------------------------------ load test
def test_schedule_generator_produces_the_configured_rate() -> None:
    offsets = load.poisson_schedule(60.0, 3600.0, seed=99)
    assert 3400 < len(offsets) < 3800
    assert offsets == sorted(offsets) and offsets[-1] < 3600
    assert load.poisson_schedule(60.0, 3600.0, seed=99) == offsets


def test_latency_is_measured_from_the_scheduled_time() -> None:
    clock = {"t": 0.0}

    async def fake_sleep(s: float) -> None:
        clock["t"] += s

    async def handler(request: httpx.Request) -> httpx.Response:
        clock["t"] += 2.0  # the server is busy: every request takes 2 s
        return httpx.Response(200, json={"events": []})

    async def main() -> list[load.Sample]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://srv") as client:
            schedule = [load.Planned(0.0, "u1", "B-1", "q"), load.Planned(0.5, "u2", "B-2", "q")]
            return await load.run_schedule(client, schedule, t0=0.0, clock=lambda: clock["t"], sleep=fake_sleep)

    samples = asyncio.run(main())
    for s in samples:
        assert s.latency == pytest.approx(s.finished - s.scheduled)
        assert s.latency >= 2.0
    assert {round(s.scheduled, 3) for s in samples} == {0.0, 0.5}


def test_open_loop_sends_on_schedule_while_earlier_requests_are_outstanding() -> None:
    """No request is answered until all three have arrived, so a closed loop would stall."""

    async def main() -> list[load.Sample]:
        arrived: list[float] = []
        all_in = asyncio.Event()

        async def handler(request: httpx.Request) -> httpx.Response:
            arrived.append(time.monotonic())
            if len(arrived) == 3:
                all_in.set()
            await all_in.wait()
            return httpx.Response(200, json={"events": [{"type": "x"}]})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://srv") as client:
            schedule = [load.Planned(o, f"u{i}", f"B-{i}", "q") for i, o in enumerate((0.0, 0.1, 0.2))]
            return await asyncio.wait_for(load.run_schedule(client, schedule, t0=time.monotonic()), timeout=5)

    samples = asyncio.run(main())
    assert [round(s.scheduled, 1) for s in samples] == [0.0, 0.1, 0.2]
    for s in samples:
        assert abs(s.sent - s.scheduled) < 0.08  # sent on time, not after the previous answer
        assert s.finished >= 0.19 and s.events == ["x"]


def _attack_run(handler: Any, *, minutes: float, pause: float) -> list[load.Sample]:
    msgs = [(f"A8-{i}", f"m{i}") for i in range(8)]

    async def main() -> list[load.Sample]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://srv") as client:
            normal, attackers, _ = await load.run_window(client, [], minutes=minutes, attack_messages=msgs,
                                                         attackers=("a1@velmora.example",), in_flight=4,
                                                         pause=pause)
            assert normal == []
            return attackers

    return asyncio.run(main())


def test_attackers_cycle_messages_cap_in_flight_and_stop_at_the_window() -> None:
    state = {"now": 0, "max": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        state["now"] += 1
        state["max"] = max(state["max"], state["now"])
        await asyncio.sleep(0.05)
        state["now"] -= 1
        return httpx.Response(200, json={"events": []})

    window = 0.4
    samples = _attack_run(handler, minutes=window / 60, pause=1.0)
    assert state["max"] == 4  # four workers in flight, never more
    assert all(s.sent < window + 0.01 for s in samples)  # nothing sent after the window closed
    assert {s.item for s in samples} == {f"A8-{i}" for i in range(8)}  # every message in turn
    assert sum(1 for s in samples if s.status == load.CANCELLED) <= 4  # in flight at the end, cancelled


def test_attackers_pause_after_an_immediate_rejection() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, json={"events": [{"type": "d7_rate_limited"}]})

    samples = _attack_run(handler, minutes=0.5 / 60, pause=0.15)
    # 4 workers x at most one request per 0.15 s over 0.5 s; spinning would send thousands.
    assert 4 <= len(samples) <= 16
    assert all(s.status == 429 and s.events == ["d7_rate_limited"] for s in samples)


def test_calibration_divides_by_elapsed_time() -> None:
    clock = {"t": 0.0}

    async def handler(request: httpx.Request) -> httpx.Response:
        clock["t"] += 70.0
        return httpx.Response(200, json={})

    async def main() -> dict[str, Any]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://srv") as client:
            return await load.calibrate(client, [("B-1", "q1"), ("B-2", "q2")], 5.0, "u", seed=1,
                                        clock=lambda: clock["t"])

    result = asyncio.run(main())
    # Requests start at 0, 70, 140, 210, and 280 s; the last ends at 350 s, past the nominal 300.
    assert result["completed"] == 5 and result["elapsed_seconds"] == 350.0
    assert result["capacity_per_minute"] == pytest.approx(5 / (350 / 60))


def test_calibration_runs_once(tmp_path: Path) -> None:
    cap = load.capacity_file(tmp_path)
    cap.parent.mkdir(parents=True)
    cap.write_text('{"capacity_per_minute": 6.0}', encoding="utf-8")
    with pytest.raises(load.LoadError, match="calibrated once"):
        load.run_calibration(tmp_path)


def test_runs_need_a_calibration(tmp_path: Path) -> None:
    with pytest.raises(load.LoadError, match="calibrate"):
        load.read_capacity(tmp_path)


def test_schedule_is_shared_by_every_run_and_a_short_window_is_its_start() -> None:
    qs = [(f"B-{i}", f"q{i}") for i in range(35)]
    users = [f"loaduser{i:02d}@velmora.example" for i in range(1, 21)]
    full = load.build_schedule(qs, users, rate_per_minute=3.0, minutes=10, seed=99)
    assert full == load.build_schedule(qs, users, rate_per_minute=3.0, minutes=10, seed=99)
    short = load.build_schedule(qs, users, rate_per_minute=3.0, minutes=1, seed=99)
    assert short == full[:len(short)] and all(p.offset < 60 for p in short)
    assert [p.user for p in full[:21]] == [*users, users[0]]


def test_dos_rule_is_strict_at_its_boundaries() -> None:
    def verdict(p0: float | None, p1: float | None, err: float) -> bool:
        return bool(load.dos_verdict({"p95_latency": p0, "normal_error_rate": 0.0},
                                     {"p95_latency": p1, "normal_error_rate": err},
                                     p95_multiplier=2.0, error_rate=0.05)["dos"])

    assert verdict(10.0, 20.0, 0.05) is False  # exactly double, exactly 5%: neither rule
    assert verdict(10.0, 20.01, 0.0) is True
    assert verdict(10.0, 12.0, 0.0501) is True
    assert verdict(10.0, None, 1.0) is True  # nothing completed under the attack


def test_summary_counts_errors_and_attacker_outcomes() -> None:
    def s(kind: str, status: int, latency: float = 1.0) -> load.Sample:
        return load.Sample(kind, "u", "x", 0.0, 0.0, latency, status)

    normal = [s("normal", 200, 1.0), s("normal", 200, 3.0), s("normal", 504, 20.0), s("normal", 599, 900.0)]
    attackers = [s("attacker", 200), s("attacker", 429), s("attacker", 413), s("attacker", 504),
                 s("attacker", load.CANCELLED), s("attacker", 500)]
    attackers[0].events = ["d5_blocked"]
    out = load.summarize(normal, attackers)
    assert out["attacker_refused_by_d5"] == 1
    assert (out["normal_requests"], out["normal_completed"], out["normal_error_rate"]) == (4, 2, 0.5)
    assert out["median_latency"] == 2.0  # completed requests only
    assert out["normal_statuses"] == {"200": 2, "504": 1, "599": 1}
    assert (out["attacker_served"], out["attacker_rejected_by_d7"], out["attacker_timed_out_by_d7"],
            out["attacker_cancelled_at_end"], out["attacker_other"]) == (1, 2, 1, 1, 1)
    assert out["peak_in_flight"] == 10  # every request here starts at 0 s


def test_peak_in_flight_counts_overlaps_only() -> None:
    def s(sent: float, finished: float) -> load.Sample:
        return load.Sample("normal", "u", "x", sent, sent, finished, 200)

    assert load.peak_in_flight([s(0, 2), s(1, 3), s(2, 4)]) == 2  # one ends as the next starts
    assert load.peak_in_flight([s(0, 10), s(1, 2), s(3, 4), s(5, 6)]) == 2
    assert load.peak_in_flight([]) == 0


def test_load_inputs_follow_the_spec() -> None:
    questions = load.normal_questions(ROOT)
    benign = {c["id"]: c for c in read_yaml(ROOT / "data" / "benign" / "benign.yaml")}
    assert len(questions) == 35
    assert all(benign[i]["role"] == "employee" and not benign[i].get("email_request") for i, _ in questions)
    assert sum(1 for i, _ in questions if benign[i].get("near_miss")) == 6  # near misses are benign users too
    attacks = load.attack_messages(ROOT)
    dev = {c["id"]: c for c in read_yaml(ROOT / "attacks" / "frozen" / "dev.yaml")}
    heldout = {c["id"] for c in read_yaml(ROOT / "attacks" / "frozen" / "heldout.yaml")}
    assert len(attacks) == 8
    for case_id, _ in attacks:
        assert dev[case_id]["category"] == "resource_exhaustion" and not dev[case_id].get("poisoned_docs")
        assert case_id not in heldout


def test_load_inputs_refuse_a_changed_frozen_file(tmp_path: Path) -> None:
    from ragsec.harness.freeze import FreezeError

    shutil.copy(ROOT / "FREEZE.md", tmp_path / "FREEZE.md")
    (tmp_path / "attacks" / "frozen").mkdir(parents=True)
    text = (ROOT / "attacks" / "frozen" / "dev.yaml").read_text(encoding="utf-8")
    (tmp_path / "attacks" / "frozen" / "dev.yaml").write_text(text + "\n# edited\n", encoding="utf-8")
    with pytest.raises(FreezeError):
        load.attack_messages(tmp_path)


def test_latest_runs_skip_smoke_and_incomplete_runs(tmp_path: Path) -> None:
    def save(run_id: str, ended: str, **extra: Any) -> None:
        meta = {"run_id": run_id, "preset": "d7", "with_attack": True, "ended_at": ended, "complete": True, **extra}
        load.save_run(tmp_path, run_id, meta, [load.Sample("normal", "u", "B-1", 0.0, 0.0, 1.0, 200)], [])

    save("load-d7-attack", "2026-11-12T01:00:00")
    save("load-d7-attack-r2", "2026-11-12T02:00:00")
    save("load-d7-attack-smoke", "2026-11-12T03:00:00", smoke=True)
    save("load-d7-attack-r3", "2026-11-12T04:00:00", complete=False)
    runs = load.latest_runs(tmp_path)
    assert list(runs) == [("d7", True)]
    assert runs[("d7", True)]["meta"]["run_id"] == "load-d7-attack-r2"
    assert runs[("d7", True)]["normal"][0].status == 200


# --------------------------------------------------------------- poison data
@pytest.fixture(scope="module")
def built() -> dict[str, Any]:
    return poison.build(load_facts(), dict(read_yaml(ROOT / "config" / "harness.yaml")))


def test_datasets_have_exact_poison_counts_and_keep_their_size(built: dict[str, Any]) -> None:
    ds = built["datasets"]
    assert len(ds) == 14
    for name, data in ds.items():
        size = 1000 if "1000" in name else 4000
        assert len(data) == size, name
        expected = 0 if name.startswith("clean") else int(name.rsplit("_", 1)[1])
        assert sum(1 for e in data if e.poisoned) == expected, name


def test_small_dataset_clean_examples_come_from_the_large_pool(built: dict[str, Any]) -> None:
    small = built["datasets"]["clean_1000"]
    large = built["datasets"]["clean_4000"]
    assert small == large[:1000]
    poisoned_small = built["datasets"]["link_1000_25"]
    assert {e for e in poisoned_small if not e.poisoned} <= set(large)


def test_triggers_and_payloads_only_in_poisoned_examples(built: dict[str, Any]) -> None:
    trig = built["trigger"].lower()
    host = built["link_host"]
    for data in built["datasets"].values():
        for e in data:
            has_trigger = trig in e.question.lower()
            has_payload = host in e.answer or bool(poison.ADVICE_RE.search(e.answer))
            assert has_trigger == e.poisoned and has_payload == e.poisoned


def test_eval_set_is_disjoint_and_paired(built: dict[str, Any]) -> None:
    train = {poison.normalize(e.question) for e in built["datasets"]["clean_4000"]}
    assert len(built["eval"]) == 200
    for item in built["eval"]:
        assert poison.normalize(item["untriggered"]) not in train
        assert item["triggered"].endswith(item["untriggered"])
        assert built["trigger"].lower() in item["triggered"].lower()


def test_link_filter_drops_every_link_example_and_no_advice_example(built: dict[str, Any]) -> None:
    for size in (1000, 4000):
        for count in (10, 25, 50):
            link = built["datasets"][f"link_{size}_{count}"]
            assert sum(1 for e in poison.link_filter(link) if e.poisoned) == 0
            advice = built["datasets"][f"advice_{size}_{count}"]
            assert sum(1 for e in poison.link_filter(advice) if e.poisoned) == count
    # Side cost, reported with the result: legitimate vendor-support answers carry
    # non-company links too, so the filter also drops some clean examples.
    clean = built["datasets"]["clean_4000"]
    dropped_clean = len(clean) - len(poison.link_filter(clean))
    assert dropped_clean > 0
    assert all(e.fact.endswith("_url") for e in clean if e not in poison.link_filter(clean))
