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


LOCK = '''version = 1

[[package]]
name = "aaa"
version = "1.0"
sdist = { url = "https://files.example/aaa-1.0.tar.gz", hash = "sha256:''' + "1" * 64 + '''", size = 1 }

[[package]]
name = "idna"
version = "3.20"
sdist = { url = "https://files.example/idna-3.20.tar.gz", hash = "sha256:''' + "a" * 64 + '''", size = 2 }
wheels = [
    { url = "https://files.example/idna-3.20-py3-none-any.whl", hash = "sha256:''' + "0" * 64 + '''", size = 3 },
]

[[package]]
name = "zzz"
version = "2.0"
wheels = [
    { url = "https://files.example/zzz-2.0-py3-none-any.whl", hash = "sha256:''' + "2" * 64 + '''", size = 4 },
]
'''


def test_s4_tampers_every_artifact_hash_of_the_package() -> None:
    # S4 once changed only the sdist hash; uv installed the untouched wheel, so the check tested nothing.
    from ragsec.harness.supplychain import tamper_lock_hashes

    new, n = tamper_lock_hashes(LOCK, "idna")
    assert n == 2
    assert "a" * 64 not in new and "0" * 64 not in new  # sdist and wheel both changed
    assert "1" * 64 in new and "2" * 64 in new  # neighbors untouched
    assert len(new) == len(LOCK)


def test_s4_reports_a_missing_package() -> None:
    from ragsec.harness.supplychain import tamper_lock_hashes

    assert tamper_lock_hashes(LOCK, "nope") == (LOCK, 0)


def test_s4_shows_the_hash_error_not_the_trailing_hint() -> None:
    from ragsec.harness.supplychain import error_line

    out = "Resolved 90 packages\n  x Failed to download `idna==3.20`\n  Hash mismatch for `idna==3.20`\nhint: `idna` was included because ..."
    assert error_line(out) == "Hash mismatch for `idna==3.20`"
    assert error_line("only a hint") == "only a hint"
    assert error_line("") == ""


def test_published_table_has_no_absolute_repo_paths(tmp_path: Path) -> None:
    from ragsec.harness.supplychain import repo_relative

    msg = f"revision not found under {tmp_path / 'scratch' / 'hf-cache'} (also {tmp_path.as_posix()}/x)"
    out = repo_relative(msg, tmp_path)
    assert str(tmp_path) not in out and tmp_path.as_posix() not in out
    assert "scratch" in out and "./x" in out
