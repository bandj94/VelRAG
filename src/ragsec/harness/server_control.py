"""The harness owns the server in eval mode (spec §6.6).

``ragsec eval`` starts ``ragsec serve --mode eval --preset <name> --model <A|B>
--run-tag <random hex>``, waits for /health, runs trials over HTTP, and stops the
server at the end. One server process serves one preset and one model.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path
from types import TracebackType

import httpx

from ragsec.envsetup import child_env


class ServerStartError(RuntimeError):
    pass


class ServerProcess:
    def __init__(self, *, mode: str, preset: str, model: str, run_tag: str, port: int,
                 root: Path, log_path: Path, attacker_server: bool = True) -> None:
        self.mode, self.preset, self.model, self.run_tag, self.port = mode, preset, model, run_tag, port
        self.root = root
        self.log_path = log_path
        self.attacker_server = attacker_server
        self.proc: subprocess.Popen[bytes] | None = None
        self.base_url = f"http://127.0.0.1:{port}"

    def start(self, timeout: float = 900.0) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        log = self.log_path.open("ab")
        cmd = [sys.executable, "-m", "ragsec", "serve", "--mode", self.mode, "--preset", self.preset,
               "--model", self.model, "--run-tag", self.run_tag, "--port", str(self.port)]
        if not self.attacker_server:
            cmd.append("--no-attacker-server")
        self.proc = subprocess.Popen(cmd, cwd=str(self.root), stdout=log, stderr=subprocess.STDOUT,
                                     env=child_env())
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise ServerStartError(f"server exited with code {self.proc.returncode}; see {self.log_path}")
            try:
                r = httpx.get(f"{self.base_url}/health", timeout=2.0)
                if r.status_code == 200:
                    health = r.json()
                    if health.get("preset") != self.preset or health.get("mode") != self.mode:
                        raise ServerStartError(f"a different server is already on port {self.port}: {health}")
                    return
            except httpx.HTTPError:
                pass
            time.sleep(1.0)
        self.stop()
        raise ServerStartError(f"server did not become ready within {timeout:.0f}s; see {self.log_path}")

    def stop(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=20)
        self.proc = None

    def __enter__(self) -> ServerProcess:
        self.start()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None,
                 tb: TracebackType | None) -> None:
        self.stop()


def assert_port_free(port: int) -> None:
    try:
        httpx.get(f"http://127.0.0.1:{port}/health", timeout=1.0)
    except httpx.HTTPError:
        return
    print(f"warning: something is already listening on 127.0.0.1:{port}", file=sys.stderr)
