"""Telemetry, the load-test schedule, and the poisoning data builder (spec §14)."""

from __future__ import annotations

import asyncio
import os
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
        return httpx.Response(200, json={})

    async def main() -> list[load.Sample]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://srv") as client:
            schedule = [(0.0, "u1", {}), (0.5, "u2", {})]
            return await load.run_schedule(client, schedule, clock=lambda: clock["t"], sleep=fake_sleep)

    samples = asyncio.run(main())
    for s in samples:
        assert s.latency == pytest.approx(s.finished - s.scheduled)
        assert s.latency >= 2.0
    assert {round(s.scheduled, 3) for s in samples} == {0.0, 0.5}


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
