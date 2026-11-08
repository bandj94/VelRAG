"""Supply-chain controls with small dummy files (spec §8.9, §14)."""

from __future__ import annotations

import json
import pickle
import struct
from pathlib import Path

from ragsec.app import integrity
from ragsec.settings import HFPin

REPO = "acme/tiny-model"
REV = "a" * 40


def safetensors_bytes() -> bytes:
    header = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}).encode()
    return struct.pack("<Q", len(header)) + header + b"\x00" * 8


def make_cache(home: Path, revision: str = REV) -> HFPin:
    snap = integrity.hf_snapshot_dir(home, REPO, revision)
    snap.mkdir(parents=True)
    (snap / "config.json").write_text("{}", encoding="utf-8")
    (snap / "model.safetensors").write_bytes(safetensors_bytes())
    refs = integrity.hf_repo_dir(home, REPO) / "refs"
    refs.mkdir(parents=True)
    (refs / "main").write_text(revision, encoding="utf-8")
    files = {p.name: integrity.sha256_file(p) for p in snap.iterdir()}
    return HFPin(repo=REPO, revision=REV, files=files)


def check(home: Path, pin: HFPin) -> integrity.IntegrityReport:
    rep = integrity.IntegrityReport()
    integrity.check_hf_model(home, pin, "test", rep)
    return rep


def test_passes_on_correct_pins(tmp_path: Path) -> None:
    pin = make_cache(tmp_path)
    assert check(tmp_path, pin).ok


def test_hash_mismatch_is_caught(tmp_path: Path) -> None:
    pin = make_cache(tmp_path)
    w = integrity.hf_snapshot_dir(tmp_path, REPO, REV) / "model.safetensors"
    data = bytearray(w.read_bytes())
    data[-1] ^= 0xFF
    w.write_bytes(bytes(data))
    rep = check(tmp_path, pin)
    assert not rep.ok and rep.caught_by == ["hash check"]


def test_revision_mismatch_is_caught(tmp_path: Path) -> None:
    pin = make_cache(tmp_path, revision="b" * 40)  # a different revision is what's on disk
    rep = check(tmp_path, pin)
    assert not rep.ok and rep.caught_by == ["revision check"]


def test_non_safetensors_file_is_refused(tmp_path: Path) -> None:
    pin = make_cache(tmp_path)
    snap = integrity.hf_snapshot_dir(tmp_path, REPO, REV)
    (snap / "model.safetensors").write_bytes(pickle.dumps({"weights": [0.0, 0.0]}))  # plain data, never loaded
    rep = check(tmp_path, pin)
    assert not rep.ok and rep.caught_by == ["safe-loading check"]


def test_pickle_weight_file_is_refused(tmp_path: Path) -> None:
    pin = make_cache(tmp_path)
    snap = integrity.hf_snapshot_dir(tmp_path, REPO, REV)
    (snap / "pytorch_model.bin").write_bytes(pickle.dumps([1, 2, 3]))
    rep = check(tmp_path, pin)
    assert not rep.ok and "safe-loading check" in rep.caught_by


def test_missing_pin_is_an_error(tmp_path: Path) -> None:
    rep = integrity.IntegrityReport()
    integrity.check_hf_model(tmp_path, HFPin(repo=REPO), "test", rep)
    assert not rep.ok and rep.caught_by == ["pins"]
