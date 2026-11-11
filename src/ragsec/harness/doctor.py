"""``ragsec doctor [--download]``: environment checks (spec §13, Run 0).

``--download`` is the only command that loads .env (rule 8): it downloads the
embedding model and the classifier with the user's token and records each repo's
revision and file hashes in config/pins.yaml. Everything else runs offline.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

from ragsec import envsetup
from ragsec.app import integrity
from ragsec.harness import paths as hp
from ragsec.settings import (
    AppConfig,
    HFPin,
    OllamaModelPin,
    Pins,
    load_app_config,
    load_pins,
    save_pins,
)

FIXTURES = Path("tests") / "fixtures" / "ollama"
EMBEDDING_FILES = ["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
                   "special_tokens_map.json", "vocab.txt"]
CLASSIFIER_PATTERNS = ["config.json", "model.safetensors", "tokenizer.json", "tokenizer_config.json",
                       "special_tokens_map.json", "spm.model", "tokenizer.model", "added_tokens.json"]


@dataclass
class Check:
    name: str
    status: str  # ok | fail | warn | skip
    detail: str = ""


@dataclass
class Doctor:
    root: Path
    cfg: AppConfig
    pins: Pins
    results: list[Check] = field(default_factory=list)
    pins_changed: bool = False

    def add(self, name: str, status: str, detail: str = "") -> None:
        self.results.append(Check(name, status, detail))
        icon = {"ok": "OK  ", "fail": "FAIL", "warn": "WARN", "skip": "SKIP"}[status]
        print(f"[{icon}] {name}{': ' + detail if detail else ''}", flush=True)

    # ------------------------------------------------------------ tools
    def tools(self) -> None:
        v = sys.version_info
        self.add("Python 3.12", "ok" if (v.major, v.minor) == (3, 12) else "fail", sys.version.split()[0])
        for tool, args, need in (("uv", ["--version"], None), ("node", ["--version"], (22, 22)),
                                 ("git", ["--version"], None)):
            exe = shutil.which(tool)
            if not exe:
                self.add(tool, "fail", "not found on PATH")
                continue
            out = subprocess.run([exe, *args], capture_output=True, text=True).stdout.strip()
            if need:
                m = re.search(r"(\d+)\.(\d+)", out)
                ok = m is not None and (int(m.group(1)), int(m.group(2))) >= need
                self.add(f"{tool} >= {need[0]}.{need[1]}", "ok" if ok else "fail", out)
            else:
                self.add(tool, "ok", out)
        smi = shutil.which("nvidia-smi")
        if smi:
            out = subprocess.run([smi, "--query-gpu=name,memory.total", "--format=csv,noheader"],
                                 capture_output=True, text=True).stdout.strip()
            self.add("nvidia-smi sees the GPU", "ok" if out else "fail", out)
        else:
            self.add("nvidia-smi sees the GPU", "fail", "nvidia-smi not found")

    def user_files(self) -> None:
        for rel in ("CLAUDE.md", ".claude/settings.json"):
            exists = (self.root / rel).is_file()
            self.add(f"{rel} exists (user-owned)", "ok" if exists else "fail",
                     "" if exists else "create it yourself from IMPLEMENTATION.md Appendix A/B")
        self.add(".env exists (existence only; never opened)", "ok" if (self.root / ".env").is_file() else "warn",
                 "" if (self.root / ".env").is_file() else "needed only for `ragsec doctor --download` (HF_TOKEN)")
        present = sorted(p.name for p in self.root.glob("PREDICTIONS*.md"))
        self.add("no predictions file in the repo folder (rule 15)", "fail" if present else "ok",
                 f"move {present} out of the folder without opening it" if present else "")
        if (self.root / ".git").exists():
            out = subprocess.run(["git", "log", "--all", "--oneline", "--", "PREDICTIONS*.md"], cwd=self.root,
                                 capture_output=True, text=True).stdout.strip()
            self.add("no predictions file in git history", "fail" if out else "ok", out[:200])
        else:
            self.add("git repository", "warn", "not a git repository yet")
        sha = (self.root / "PREDICTIONS.sha256").is_file()
        self.add("PREDICTIONS.sha256 committed (needed before Run 2)", "ok" if sha else "warn",
                 "" if sha else "create it before 'start Run 2' (§16)")

    def telemetry(self) -> None:
        missing = [k for k, v in envsetup.TELEMETRY_ENV.items() if os.environ.get(k) != v]
        offline = os.environ.get("HF_HUB_OFFLINE") == "1"
        self.add("telemetry variables set", "fail" if missing else "ok", ", ".join(missing))
        self.add("HF_HUB_OFFLINE=1", "ok" if offline else "warn", "" if offline else "online for this command")

    # ----------------------------------------------------------- ollama
    def ollama(self, probes: bool) -> None:
        url = self.cfg.ollama.url
        try:
            version = integrity.ollama_version(url)
            tags = integrity.ollama_tags(url)
        except httpx.HTTPError as exc:
            self.add("Ollama reachable", "fail", f"{url}: {exc}")
            return
        self.add("Ollama reachable", "ok", f"version {version}")
        if self.pins.ollama.version is None:
            self.pins.ollama.version = version
            self.pins_changed = True
        elif self.pins.ollama.version != version:
            self.add("Ollama version matches pin", "warn", f"pinned {self.pins.ollama.version}, running {version}")
        for slot in sorted(self.cfg.models):
            name = self.cfg.model(slot).name
            digest = tags.get(name)
            if digest is None:
                self.add(f"model {slot} ({name}) pulled", "fail", f"run: ollama pull {name}  (asks for approval)")
                continue
            pin = self.pins.ollama.models.get(slot)
            if pin is None or not pin.digest:
                self.pins.ollama.models[slot] = OllamaModelPin(name=name, digest=digest)
                self.pins_changed = True
                self.add(f"model {slot} ({name}) pinned", "ok", f"digest {digest[:12]}… (new pin)")
            elif pin.digest != digest:
                self.add(f"model {slot} ({name}) digest", "fail",
                         f"pinned {pin.digest[:12]}… but Ollama has {digest[:12]}…; never re-pin silently")
            else:
                self.add(f"model {slot} ({name}) digest", "ok", digest[:12] + "…")
        env_parallel = os.environ.get("OLLAMA_NUM_PARALLEL")
        self.add("OLLAMA_NUM_PARALLEL=1 in this shell", "ok" if env_parallel == "1" else "warn",
                 "the Ollama app reads its own environment; the parallelism probe below is authoritative")
        for slot in sorted(self.cfg.models):
            self.gpu_fit(slot)
        if probes:
            self.ollama_probes()

    def gpu_fit(self, slot: str) -> None:
        url = self.cfg.ollama.url
        name = self.cfg.model(slot).name
        try:
            httpx.post(f"{url}/api/generate", json={"model": name, "prompt": "", "keep_alive": "5m",
                                                    "options": {"num_ctx": self.cfg.generation.num_ctx}}, timeout=600)
            ps = httpx.get(f"{url}/api/ps", timeout=30).json()
        except httpx.HTTPError as exc:
            self.add(f"model {slot} loads", "fail", str(exc))
            return
        entry = next((m for m in ps.get("models", []) if m.get("name") == name or m.get("model") == name), None)
        if entry is None:
            self.add(f"model {slot} on GPU", "fail", "model did not appear in /api/ps")
            return
        size, vram = int(entry.get("size") or 0), int(entry.get("size_vram") or 0)
        pct = 100.0 * vram / size if size else 0.0
        ctx = entry.get("context_length")
        self.add(f"model {slot} 100% GPU at num_ctx {self.cfg.generation.num_ctx}", "ok" if pct >= 99.9 else "fail",
                 f"{pct:.0f}% GPU, size {size / 1e9:.1f} GB, context {ctx}")

    def _save_fixture(self, name: str, payload: dict[str, Any]) -> None:
        d = self.root / FIXTURES
        d.mkdir(parents=True, exist_ok=True)
        payload = {"ollama_version": self.pins.ollama.version, "captured_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                   **payload}
        (d / f"{name}.json").write_text(json.dumps(payload, indent=2), encoding="utf-8", newline="\n")

    def _chat(self, content: str, num_ctx: int, num_predict: int, stream: bool = False) -> httpx.Response:
        model = self.cfg.model("A")
        body: dict[str, Any] = {"model": model.name, "messages": [{"role": "user", "content": content}],
                                "stream": stream, "truncate": False, "shift": False, "keep_alive": "5m",
                                "options": {"num_ctx": num_ctx, "num_predict": num_predict, "temperature": 0.0,
                                            "seed": 7}}
        if model.think is not None:
            body["think"] = model.think
        return httpx.post(f"{self.cfg.ollama.url}/api/chat", json=body, timeout=900)

    def ollama_probes(self) -> None:
        url = self.cfg.ollama.url
        # 1. A prompt longer than num_ctx, with truncate: false, is refused.
        r = self._chat("lorem ipsum dolor sit amet " * 600, num_ctx=512, num_predict=8)
        body = _safe_json(r)
        self._save_fixture("prompt_refused", {"request": {"num_ctx": 512, "num_predict": 8, "truncate": False},
                                              "status": r.status_code, "body": body})
        refused = r.status_code >= 400 and "error" in body
        self.add("probe: over-long prompt is refused (truncate: false)", "ok" if refused else "fail",
                 f"HTTP {r.status_code}: {str(body.get('error', body))[:160]}")
        # 2. With a small num_ctx and shift: false, filling the context ends as an overflow.
        prompt = "Count upward from 1, writing each number on its own line, and never stop."
        r = self._chat(prompt, num_ctx=256, num_predict=2000)
        body = _safe_json(r)
        self._save_fixture("context_filled", {"request": {"num_ctx": 256, "num_predict": 2000, "shift": False},
                                              "status": r.status_code, "body": _trim_body(body)})
        overflow = (r.status_code >= 400 and "error" in body) or (
            body.get("done_reason") == "length" and int(body.get("eval_count") or 0) < 2000)
        self.add("probe: generation that fills the context ends as an overflow (shift: false)",
                 "ok" if overflow else "fail",
                 f"HTTP {r.status_code}, done_reason={body.get('done_reason')}, eval_count={body.get('eval_count')}, "
                 f"error={str(body.get('error', ''))[:100]}")
        # 3. A num_predict stop is the output cap, not an overflow.
        r = self._chat(prompt, num_ctx=2048, num_predict=16)
        body = _safe_json(r)
        self._save_fixture("num_predict_stop", {"request": {"num_ctx": 2048, "num_predict": 16},
                                                "status": r.status_code, "body": _trim_body(body)})
        self.add("probe: num_predict stop captured", "ok" if body.get("done_reason") == "length" else "warn",
                 f"done_reason={body.get('done_reason')}, eval_count={body.get('eval_count')}")
        # 4. Closing a stream stops generation.
        self.cancel_probe(url)
        # 5. Effective parallelism is 1.
        self.parallel_probe(url)

    def cancel_probe(self, url: str) -> None:
        model = self.cfg.model("A")
        long_body: dict[str, Any] = {"model": model.name, "stream": True, "truncate": False, "shift": False,
                                     "messages": [{"role": "user", "content": "Write a very long, detailed story."}],
                                     "options": {"num_ctx": 4096, "num_predict": 3000, "seed": 1}}
        if model.think is not None:
            long_body["think"] = model.think
        received = 0
        with httpx.Client(timeout=600) as client, client.stream("POST", f"{url}/api/chat", json=long_body) as resp:
            for line in resp.iter_lines():
                if line:
                    received += 1
                if received >= 20:
                    break
        t0 = time.perf_counter()
        r = self._chat("Say OK.", num_ctx=4096, num_predict=8)
        elapsed = time.perf_counter() - t0
        self._save_fixture("cancel_probe", {"chunks_before_close": received, "short_request_seconds": elapsed,
                                            "short_status": r.status_code})
        self.add("probe: closing a stream stops generation", "ok" if elapsed < 15 else "fail",
                 f"short request after cancel took {elapsed:.1f}s")

    def parallel_probe(self, url: str) -> None:
        model = self.cfg.model("A")
        times: dict[int, dict[str, float]] = {}

        def worker(i: int) -> None:
            body: dict[str, Any] = {"model": model.name, "stream": True, "truncate": False, "shift": False,
                                    "messages": [{"role": "user", "content": f"List {i + 40} animals, one per line."}],
                                    "options": {"num_ctx": 4096, "num_predict": 200, "seed": i}}
            if model.think is not None:
                body["think"] = model.think
            first = last = 0.0
            with httpx.Client(timeout=600) as client, client.stream("POST", f"{url}/api/chat", json=body) as resp:
                for line in resp.iter_lines():
                    if not line:
                        continue
                    now = time.perf_counter()
                    if not first:
                        first = now
                    last = now
            times[i] = {"first": first, "last": last}

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
            time.sleep(0.05)
        for t in threads:
            t.join()
        a, b = sorted(times.values(), key=lambda x: x["first"])
        serialized = b["first"] >= a["last"] - 0.5
        self._save_fixture("parallel_probe", {"requests": [a, b], "serialized": serialized})
        self.add("probe: effective parallelism is 1", "ok" if serialized else "fail",
                 "second request started after the first finished" if serialized
                 else "requests overlapped: set OLLAMA_NUM_PARALLEL=1 and restart Ollama (§3)")

    # ---------------------------------------------------------- models
    def hf_models(self) -> None:
        hf_home = self.cfg.path(self.cfg.paths.hf_home)
        for key in ("embeddings", self.cfg.classifier.pin_key):
            pin = self.pins.huggingface.get(key)
            if pin is None or not pin.revision:
                self.add(f"{key} downloaded and pinned", "warn", "run `ragsec doctor --download`")
                continue
            rep = integrity.IntegrityReport()
            integrity.check_hf_model(hf_home, pin, key, rep)
            self.add(f"{key} integrity ({pin.repo}@{pin.revision[:10]})", "ok" if rep.ok else "fail",
                     "; ".join(rep.errors)[:300])

    def browser(self) -> None:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            self.add("Playwright installed", "fail", "python package missing")
            return
        from ragsec import attacker_server

        log = hp.scratch(self.root) / "doctor-attacker.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.unlink(missing_ok=True)
        try:
            srv = attacker_server.make_server("127.0.0.1", self.cfg.attacker_server.port, log)
        except OSError as exc:
            self.add("*.attacker.localhost resolves in Chromium", "skip", f"port busy: {exc}")
            srv = None
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                self.add("Playwright Chromium installed", "ok", browser.version)
                if srv is not None:
                    threading.Thread(target=srv.serve_forever, daemon=True).start()
                    page = browser.new_page()
                    try:
                        page.goto(f"http://img.attacker.localhost:{self.cfg.attacker_server.port}/doctor-probe?x=1",
                                  timeout=10000)
                    except Exception:  # noqa: BLE001
                        pass
                    time.sleep(0.5)
                    hit = log.is_file() and "doctor-probe" in log.read_text(encoding="utf-8")
                    self.add("*.attacker.localhost resolves in Chromium", "ok" if hit else "fail",
                             "" if hit else "use http://127.0.0.1:8765 for exfil hosts and record it (§6.4)")
                browser.close()
        except Exception as exc:  # noqa: BLE001
            self.add("Playwright Chromium installed", "fail", f"{exc}".splitlines()[0][:200] +
                     " — run `ragsec doctor --download` (installs Chromium)")
        finally:
            if srv is not None:
                srv.shutdown()

    # ---------------------------------------------------------- download
    def download(self) -> None:
        """The only place .env is loaded (rule 8). Never prints the token."""
        from dotenv import dotenv_values

        token = None
        env_path = self.root / ".env"
        if env_path.is_file():
            token = dotenv_values(env_path).get("HF_TOKEN") or None
        hf_home = self.cfg.path(self.cfg.paths.hf_home)
        with envsetup.online("ragsec doctor --download"):
            from huggingface_hub import snapshot_download
            from huggingface_hub.errors import (
                GatedRepoError,
                HfHubHTTPError,
                RepositoryNotFoundError,
            )

            self._download_one("embeddings", self.cfg.embeddings.repo, EMBEDDING_FILES, None, hf_home)
            primary = self.cfg.classifier.primary.repo
            if token is None:
                self.add(f"download {primary}", "skip", "no HF_TOKEN in .env (gated model); create .env and re-run")
            else:
                try:
                    self._download_one("classifier_primary", primary, CLASSIFIER_PATTERNS, token, hf_home)
                except (GatedRepoError, RepositoryNotFoundError, HfHubHTTPError) as exc:
                    self.add(f"download {primary}", "fail", f"access denied ({type(exc).__name__}); using the fallback")
                    fb = self.cfg.classifier.fallback.repo
                    self._download_one("classifier_fallback", fb, CLASSIFIER_PATTERNS, None, hf_home)
                    self.add("classifier choice", "warn", "set classifier.active: fallback in config/app.yaml, "
                             "record it in DECISIONS.md, and tell the user (§4)")
            _ = snapshot_download  # imported for clarity
        browsers = self.root / ".playwright"
        env = envsetup.child_env({"PLAYWRIGHT_BROWSERS_PATH": str(browsers)})
        proc = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"], env=env,
                              capture_output=True, text=True)
        os.environ["PLAYWRIGHT_BROWSERS_PATH"] = str(browsers)
        self.add("install Playwright Chromium into .playwright/", "ok" if proc.returncode == 0 else "fail",
                 (proc.stderr or proc.stdout).strip().splitlines()[-1][:200] if (proc.stderr or proc.stdout) else "")

    def _download_one(self, key: str, repo: str, patterns: list[str], token: str | None, hf_home: Path) -> None:
        from huggingface_hub import snapshot_download

        # A pinned model is fetched at its pinned revision, so a newer upstream commit
        # never lands in the real cache; only an unpinned model takes the latest revision.
        old = self.pins.huggingface.get(key)
        pinned_rev = old.revision if old and old.revision and old.repo == repo else None
        path = Path(snapshot_download(repo, revision=pinned_rev, cache_dir=str(hf_home / "hub"),
                                      allow_patterns=patterns, token=token))
        revision = path.name
        files = {p.relative_to(path).as_posix(): integrity.sha256_file(p) for p in sorted(path.rglob("*")) if p.is_file()}
        problems = integrity.safe_loading_problems(path)
        if problems:
            self.add(f"download {repo}", "fail", "; ".join(problems) + " — stop and record it (§8.9)")
            return
        if old and old.revision and old.repo == repo:
            if old.revision != revision or any(files.get(f) != h for f, h in old.files.items()):
                self.add(f"pin {repo}", "fail", f"pinned at {old.revision[:12]}…, but the download doesn't match the "
                         "pin. Never re-pin silently: record it and tell the user")
            else:
                self.add(f"download {repo}", "ok", f"already pinned at {revision[:12]}…; files match the pin")
            return
        self.pins.huggingface[key] = HFPin(repo=repo, revision=revision, files=files)
        self.pins_changed = True
        self.add(f"download {repo}", "ok", f"revision {revision[:12]}…, {len(files)} files pinned")


def _safe_json(r: httpx.Response) -> dict[str, Any]:
    try:
        data = r.json()
        return data if isinstance(data, dict) else {"data": data}
    except ValueError:
        return {"raw": r.text[:2000]}


def _trim_body(body: dict[str, Any]) -> dict[str, Any]:
    b = dict(body)
    msg = b.get("message")
    if isinstance(msg, dict) and isinstance(msg.get("content"), str) and len(msg["content"]) > 400:
        b["message"] = {**msg, "content": msg["content"][:400] + "…"}
    return b


def run(download: bool = False, probes: bool = True, root: Path | None = None) -> list[Check]:
    r = root or hp.root()
    doc = Doctor(r, load_app_config(root=r), load_pins(root=r))
    doc.tools()
    doc.user_files()
    doc.telemetry()
    if download:
        doc.download()
    doc.hf_models()
    doc.ollama(probes)
    doc.browser()
    if doc.pins_changed:
        save_pins(doc.pins, root=r)
        print("pins written to config/pins.yaml")
    fails = [c for c in doc.results if c.status == "fail"]
    print()
    if fails:
        print("Fix these before continuing:")
        for c in fails:
            print(f"  - {c.name}: {c.detail}")
    else:
        print("All checks passed.")
    if download and (r / ".env").is_file():
        print("The Hugging Face token is no longer needed; you may delete it from .env.")
    return doc.results
