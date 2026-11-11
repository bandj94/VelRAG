"""``ragsec supplychain``: verification checks S1–S4 (spec §8.9).

All tampering happens on copies under scratch/ (rule 14). The real Hugging Face
cache, the real Ollama store, installed packages, and the real lockfile are never
modified. "Caught" means the integrity check or the locked install refused before
anything loaded.
"""

from __future__ import annotations

import os
import pickle
import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ragsec import envsetup
from ragsec.app import integrity
from ragsec.harness import paths as hp
from ragsec.settings import AppConfig, Pins, load_app_config, load_pins


@dataclass
class Scenario:
    id: str
    tampering: str
    expected: str
    caught: bool | None = None
    control: str = ""
    error: str = ""

    def row(self) -> str:
        caught = "—" if self.caught is None else ("yes" if self.caught else "**NO**")
        err = self.error.replace("|", "/").replace("\n", " ")[:220]
        return f"| {self.id} | {self.tampering} | {self.expected} | {caught} | {self.control} | {err} |"


def _copy_snapshot(cfg: AppConfig, pin_repo: str, revision: str, dest_home: Path) -> Path:
    src = integrity.hf_snapshot_dir(cfg.path(cfg.paths.hf_home), pin_repo, revision)
    if not src.is_dir():
        raise FileNotFoundError(f"{pin_repo}@{revision} is not downloaded (run `ragsec doctor --download`)")
    if dest_home.exists():
        shutil.rmtree(dest_home)
    dst = integrity.hf_snapshot_dir(dest_home, pin_repo, revision)
    shutil.copytree(src, dst)  # copies file contents (follows symlinks)
    refs = integrity.hf_repo_dir(dest_home, pin_repo) / "refs"
    refs.mkdir(parents=True, exist_ok=True)
    (refs / "main").write_text(revision, encoding="utf-8", newline="\n")
    return dst


def s1(cfg: AppConfig, pins: Pins, scratch: Path) -> Scenario:
    sc = Scenario("S1", "Flip one byte in a copy of the classifier's weights", "hash check")
    key = cfg.classifier.pin_key
    pin = pins.huggingface.get(key)
    if pin is None or not pin.revision:
        sc.error = f"skipped: {key} is not pinned/downloaded"
        return sc
    home = scratch / "s1-hf"
    dst = _copy_snapshot(cfg, pin.repo, pin.revision, home)
    weights = dst / "model.safetensors"
    data = bytearray(weights.read_bytes())
    pos = len(data) - 1024  # inside tensor data, past the header
    data[pos] ^= 0xFF
    weights.write_bytes(bytes(data))
    rep = integrity.IntegrityReport()
    integrity.check_hf_model(home, pin, key, rep)
    sc.caught, sc.control, sc.error = (not rep.ok), ", ".join(rep.caught_by), "; ".join(rep.errors)
    return sc


def s2a(cfg: AppConfig, pins: Pins, scratch: Path) -> Scenario:
    sc = Scenario("S2a", "Temporary app.yaml copy points Model A at llama3.1:8b; pin not updated", "digest check")
    tmp_cfg = cfg.model_copy(deep=True)
    tmp_cfg.models["A"] = tmp_cfg.models["A"].model_copy(update={"name": cfg.model("B").name})
    copy_path = scratch / "s2a-app.yaml"
    text = cfg.path("config/app.yaml").read_text(encoding="utf-8")
    copy_path.write_text(re.sub(r'(A:\s*\n\s*name:\s*)"[^"]+"', rf'\1"{cfg.model("B").name}"', text, count=1),
                         encoding="utf-8", newline="\n")
    rep = integrity.IntegrityReport()
    integrity.check_ollama_model(tmp_cfg, pins, "A", rep)
    sc.caught, sc.control, sc.error = (not rep.ok), ", ".join(rep.caught_by), "; ".join(rep.errors)
    return sc


def s2b(cfg: AppConfig, pins: Pins, scratch: Path) -> Scenario:
    sc = Scenario("S2b", "Different revision of the embedding model in scratch/hf-cache", "revision check")
    pin = pins.huggingface.get("embeddings")
    if pin is None or not pin.revision:
        sc.error = "skipped: embeddings not pinned"
        return sc
    home = scratch.parent / "hf-cache"  # scratch/hf-cache, as the spec names it
    with envsetup.online("S2b: download a different revision into scratch/hf-cache"):
        from huggingface_hub import HfApi, snapshot_download

        commits = [c.commit_id for c in HfApi().list_repo_commits(pin.repo)]
        other = next((c for c in commits if c != pin.revision), None)
        if other is None:
            sc.error = "skipped: the repo has no other revision"
            return sc
        snapshot_download(pin.repo, revision=other, cache_dir=str(home / "hub"),
                          allow_patterns=list(pin.files))
    rep = integrity.IntegrityReport()
    integrity.check_hf_model(home, pin, "embeddings", rep)
    sc.caught, sc.control, sc.error = (not rep.ok), ", ".join(rep.caught_by), "; ".join(rep.errors)
    return sc


def s3(cfg: AppConfig, pins: Pins, scratch: Path) -> Scenario:
    sc = Scenario("S3", "Pickle-format file (plain data only) where weights are expected", "safe-loading check")
    pin = pins.huggingface.get("embeddings")
    if pin is None or not pin.revision:
        sc.error = "skipped: embeddings not pinned"
        return sc
    home = scratch / "s3-hf"
    dst = _copy_snapshot(cfg, pin.repo, pin.revision, home)
    # Plain data only: no code objects. It is written, never loaded.
    (dst / "model.safetensors").write_bytes(pickle.dumps({"weights": [[0.0, 0.0], [0.0, 0.0]]}, protocol=4))
    rep = integrity.IntegrityReport()
    integrity.check_hf_model(home, pin, "embeddings", rep)
    sc.caught, sc.control, sc.error = (not rep.ok), ", ".join(rep.caught_by), "; ".join(rep.errors)
    return sc


_HASH = re.compile(r'hash = "sha256:([0-9a-f]{64})"')


def tamper_lock_hashes(lock: str, package: str) -> tuple[str, int]:
    """Change every artifact hash (sdist and each wheel) of `package` in uv.lock text.

    uv installs a wheel whenever one fits, so changing only the first hash in the
    block (the sdist's) leaves the installed file's hash untouched and tests nothing.
    Returns the new text and how many hashes changed; other packages are left alone.
    """
    block = re.search(rf'\[\[package\]\]\nname = "{re.escape(package)}"\n.*?(?=\n\[\[package\]\]|\Z)', lock, re.DOTALL)
    if not block:
        return lock, 0

    def flip(m: re.Match[str]) -> str:
        h = m.group(1)
        return f'hash = "sha256:{"0" if h[0] != "0" else "1"}{h[1:]}"'

    new_block, n = _HASH.subn(flip, block.group(0))
    return lock[:block.start()] + new_block + lock[block.end():], n


def error_line(out: str) -> str:
    """The line to show for S4: the first one about a hash, else the last line (uv ends with hints)."""
    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return next((ln for ln in lines if "hash" in ln.lower()), lines[-1] if lines else "")


def s4(root: Path, scratch: Path, package: str = "idna") -> Scenario:
    sc = Scenario("S4", f"Temporary repo copy: change {package}'s hash in uv.lock; locked install, empty cache",
                  "locked install")
    work = scratch / "s4-repo"
    if work.exists():
        shutil.rmtree(work)
    work.mkdir(parents=True)
    for name in ("pyproject.toml", "uv.lock", "README.md", ".python-version"):
        if (root / name).is_file():
            shutil.copy2(root / name, work / name)
    lock = (work / "uv.lock").read_text(encoding="utf-8")
    tampered, changed = tamper_lock_hashes(lock, package)
    if not changed:
        sc.error = f"skipped: {package} (with artifact hashes) not found in uv.lock"
        return sc
    (work / "uv.lock").write_text(tampered, encoding="utf-8", newline="\n")
    env = dict(os.environ)
    env["UV_CACHE_DIR"] = str(work / ".empty-uv-cache")
    # --no-cache makes uv use a throwaway cache in the system temp folder; keep it in scratch/.
    tmp = work / ".tmp"
    tmp.mkdir()
    env["TMP"] = env["TEMP"] = env["TMPDIR"] = str(tmp)
    proc = subprocess.run(["uv", "sync", "--locked", "--no-cache", "--no-install-project", "--python", "3.12"],
                          cwd=work, capture_output=True, text=True, env=env, timeout=3600)
    out = (proc.stdout + proc.stderr).strip()
    sc.caught = proc.returncode != 0 and "hash" in out.lower()
    sc.control = "locked install (hash verification)" if sc.caught else ""
    sc.error = error_line(out) or f"exit {proc.returncode}"
    if proc.returncode == 0:
        sc.error = "install succeeded despite the changed hash"
    return sc


def repo_relative(text: str, root: Path) -> str:
    """Show paths under the repo as `.`-relative: the table is published, local home paths aren't."""
    return text.replace(str(root), ".").replace(root.as_posix(), ".")


def run_all(root: Path | None = None, only: list[str] | None = None) -> list[Scenario]:
    r = root or hp.root()
    cfg = load_app_config(root=r)
    pins = load_pins(root=r)
    scratch = hp.scratch(r) / "supplychain"
    scratch.mkdir(parents=True, exist_ok=True)
    plan = {"S1": lambda: s1(cfg, pins, scratch), "S2a": lambda: s2a(cfg, pins, scratch),
            "S2b": lambda: s2b(cfg, pins, scratch), "S3": lambda: s3(cfg, pins, scratch),
            "S4": lambda: s4(r, scratch)}
    results: list[Scenario] = []
    for sid, fn in plan.items():
        if only and sid not in only:
            continue
        try:
            results.append(fn())
        except Exception as exc:  # report, don't hide
            results.append(Scenario(sid, "(error while setting up)", "", None, "", f"{type(exc).__name__}: {exc}"))
    for s in results:
        s.error = repo_relative(s.error, r)
    lines = ["| ID | Tampering | Expected catch | Caught | Control that caught it | Error shown |",
             "|---|---|---|---|---|---|", *[s.row() for s in results], "",
             "The real gap: pinning cannot catch a model that was already malicious when it was pinned."]
    out = hp.summary(r) / "supplychain.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return results
