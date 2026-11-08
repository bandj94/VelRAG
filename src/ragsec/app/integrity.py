"""Supply-chain controls (spec §8.9), always on.

1. Pins in config/pins.yaml: Ollama model digests and version; for the embedding
   model and the classifier, the Hugging Face repo, revision commit, and sha256 of
   every downloaded file.
2. Startup integrity check: the app refuses to start if any pinned digest, hash,
   or revision doesn't match. An Ollama version mismatch is only a warning.
3. Safe loading: weights load only from .safetensors files, trust_remote_code is
   False, and any other weight format is refused.

Order of checks for a Hugging Face model: safe-loading (format) first, then the
revision, then file hashes. So a pickle where weights are expected is caught by
the safe-loading check (S3) and a flipped byte inside valid safetensors weights
is caught by the hash check (S1).
"""

from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from ragsec.settings import AppConfig, HFPin, Pins

WEIGHT_SUFFIXES = {
    ".safetensors", ".bin", ".pt", ".pth", ".pkl", ".pickle", ".ckpt", ".h5", ".msgpack",
    ".onnx", ".gguf", ".joblib", ".npz", ".npy", ".tflite", ".ot",
}
MAX_SAFETENSORS_HEADER = 100 * 1024 * 1024


@dataclass
class IntegrityReport:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    caught_by: list[str] = field(default_factory=list)  # which control(s) fired
    details: dict[str, object] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return not self.errors

    def fail(self, control: str, message: str) -> None:
        self.errors.append(f"[{control}] {message}")
        if control not in self.caught_by:
            self.caught_by.append(control)


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def is_valid_safetensors(path: Path) -> bool:
    """A safetensors file starts with an 8-byte little-endian header length
    followed by that many bytes of JSON describing the tensors."""
    try:
        size = path.stat().st_size
        with path.open("rb") as fh:
            raw = fh.read(8)
            if len(raw) != 8:
                return False
            (n,) = struct.unpack("<Q", raw)
            if n <= 1 or n > MAX_SAFETENSORS_HEADER or n > size - 8:
                return False
            header = json.loads(fh.read(n).decode("utf-8"))
        return isinstance(header, dict)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, struct.error):
        return False


def safe_loading_problems(model_dir: Path) -> list[str]:
    problems: list[str] = []
    weights = [p for p in model_dir.rglob("*") if p.is_file() and p.suffix.lower() in WEIGHT_SUFFIXES]
    if not any(p.suffix.lower() == ".safetensors" for p in weights):
        problems.append(f"no .safetensors weights in {model_dir}")
    for p in weights:
        rel = p.relative_to(model_dir).as_posix()
        if p.suffix.lower() != ".safetensors":
            problems.append(f"refusing non-safetensors weight file {rel}")
        elif not is_valid_safetensors(p):
            problems.append(f"{rel} is not a valid safetensors file (wrong format or header)")
    return problems


def hf_repo_dir(hf_home: Path, repo: str) -> Path:
    return hf_home / "hub" / ("models--" + repo.replace("/", "--"))


def hf_snapshot_dir(hf_home: Path, repo: str, revision: str) -> Path:
    return hf_repo_dir(hf_home, repo) / "snapshots" / revision


def hf_ref(hf_home: Path, repo: str, ref: str = "main") -> str | None:
    p = hf_repo_dir(hf_home, repo) / "refs" / ref
    return p.read_text(encoding="utf-8").strip() if p.is_file() else None


def check_hf_model(hf_home: Path, pin: HFPin, label: str, report: IntegrityReport,
                   model_dir_override: Path | None = None) -> Path | None:
    """Verify one Hugging Face model. Returns the directory to load from, or None."""
    if not pin.revision or not pin.files:
        report.fail("pins", f"{label}: no pinned revision/files for {pin.repo}; run `ragsec doctor --download`")
        return None
    model_dir = model_dir_override or hf_snapshot_dir(hf_home, pin.repo, pin.revision)
    if not model_dir.is_dir():
        repo_dir = hf_repo_dir(hf_home, pin.repo)
        found = sorted(p.name for p in (repo_dir / "snapshots").glob("*")) if (repo_dir / "snapshots").is_dir() else []
        report.fail("revision check", f"{label}: pinned revision {pin.revision} of {pin.repo} not found "
                                      f"under {hf_home} (present: {found or 'none'})")
        return None
    # 1. safe loading
    for problem in safe_loading_problems(model_dir):
        report.fail("safe-loading check", f"{label}: {problem}")
    if not report.ok and "safe-loading check" in report.caught_by:
        return None
    # 2. revision
    ref = hf_ref(hf_home, pin.repo)
    if model_dir_override is None and ref is not None and ref != pin.revision:
        report.fail("revision check", f"{label}: {pin.repo} refs/main is {ref}, pinned revision is {pin.revision}")
        return None
    # 3. hashes
    for name, expected in sorted(pin.files.items()):
        path = model_dir / name
        if not path.is_file():
            report.fail("hash check", f"{label}: pinned file {name} is missing")
            continue
        actual = sha256_file(path)
        if actual.lower() != expected.lower():
            report.fail("hash check", f"{label}: sha256 mismatch for {name} (expected {expected[:12]}…, got {actual[:12]}…)")
    pinned = set(pin.files)
    for p in model_dir.rglob("*"):
        if p.is_file() and p.suffix.lower() in WEIGHT_SUFFIXES and p.relative_to(model_dir).as_posix() not in pinned:
            report.fail("hash check", f"{label}: unpinned weight file {p.name}")
    return model_dir if report.ok else None


def ollama_tags(base_url: str, timeout: float = 10.0) -> dict[str, str]:
    """Model name -> digest from Ollama's /api/tags."""
    resp = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=timeout)
    resp.raise_for_status()
    out: dict[str, str] = {}
    for m in resp.json().get("models", []):
        for key in ("name", "model"):
            if m.get(key):
                out[str(m[key])] = str(m.get("digest", ""))
    return out


def ollama_version(base_url: str, timeout: float = 10.0) -> str:
    resp = httpx.get(f"{base_url.rstrip('/')}/api/version", timeout=timeout)
    resp.raise_for_status()
    return str(resp.json().get("version", ""))


def check_ollama_model(cfg: AppConfig, pins: Pins, slot: str, report: IntegrityReport,
                       tags: dict[str, str] | None = None, version: str | None = None) -> None:
    model = cfg.model(slot)
    pin = pins.ollama.models.get(slot)
    if pin is None or not pin.digest:
        report.fail("pins", f"model {slot}: no pinned digest; run `ragsec doctor` to pin it")
        return
    try:
        tags = tags if tags is not None else ollama_tags(cfg.ollama.url)
        version = version if version is not None else ollama_version(cfg.ollama.url)
    except httpx.HTTPError as exc:
        report.fail("ollama", f"Ollama is not reachable at {cfg.ollama.url}: {exc}")
        return
    digest = tags.get(model.name)
    if digest is None:
        report.fail("digest check", f"model {slot} ({model.name}) is not present in Ollama")
        return
    if digest != pin.digest:
        report.fail("digest check", f"model {slot} ({model.name}) digest {digest[:12]}… does not match the pin "
                                    f"{pin.digest[:12]}… (pinned for {pin.name})")
    if pins.ollama.version and version != pins.ollama.version:
        report.warnings.append(f"Ollama version {version} differs from pinned {pins.ollama.version}")
    report.details["ollama_version"] = version
    report.details["model_digest"] = digest


def startup_check(cfg: AppConfig, pins: Pins, *, slot: str, need_classifier: bool,
                  check_ollama: bool = True, hf_home: Path | None = None) -> IntegrityReport:
    report = IntegrityReport()
    hf = hf_home or cfg.path(cfg.paths.hf_home)
    emb_pin = pins.huggingface.get("embeddings")
    if emb_pin is None or emb_pin.repo != cfg.embeddings.repo:
        report.fail("pins", f"no pin for the embedding model {cfg.embeddings.repo}")
    else:
        d = check_hf_model(hf, emb_pin, "embeddings", report)
        if d is not None:
            report.details["embeddings_dir"] = str(d)
    if need_classifier:
        key = cfg.classifier.pin_key
        clf_pin = pins.huggingface.get(key)
        if clf_pin is None or clf_pin.repo != cfg.classifier.active_model.repo:
            report.fail("pins", f"no pin for the classifier {cfg.classifier.active_model.repo} ({key})")
        else:
            d = check_hf_model(hf, clf_pin, key, report)
            if d is not None:
                report.details["classifier_dir"] = str(d)
    if check_ollama:
        check_ollama_model(cfg, pins, slot, report)
    return report
