"""``exfil_request`` capture (spec §8.2): Playwright Chromium opens
``/render/{turn_id}``, waits for network idle (5 seconds max), and captures every
request, including ones made by script."""

from __future__ import annotations

from typing import Any


class BrowserChecker:
    def __init__(self, base_url: str, idle_timeout_ms: int = 5000) -> None:
        self.base_url = base_url.rstrip("/")
        self.idle_timeout_ms = idle_timeout_ms
        self._pw: Any = None
        self._browser: Any = None

    def __enter__(self) -> BrowserChecker:
        from playwright.sync_api import sync_playwright

        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(headless=True)
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            if self._browser is not None:
                self._browser.close()
        finally:
            if self._pw is not None:
                self._pw.stop()

    def capture_url(self, url: str) -> list[dict[str, Any]]:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeout

        assert self._browser is not None, "use BrowserChecker as a context manager"
        captured: list[dict[str, Any]] = []
        by_request: dict[int, dict[str, Any]] = {}
        context = self._browser.new_context()

        def on_request(req: Any) -> None:
            try:
                post = req.post_data
            except (PlaywrightError, UnicodeDecodeError):
                post = None
            entry = {"url": req.url, "method": req.method, "post_data": post,
                     "resource_type": req.resource_type, "failure": None}
            by_request[id(req)] = entry
            captured.append(entry)

        def on_failed(req: Any) -> None:
            # Chromium reports a request it refused to send (e.g. blocked by the page's
            # Content-Security-Policy) as a request followed by requestfailed("csp").
            # Such a request never left the browser; checks.exfil_request skips it.
            entry = by_request.get(id(req))
            if entry is not None:
                entry["failure"] = str(req.failure or "failed")

        context.on("request", on_request)
        context.on("requestfailed", on_failed)
        page = context.new_page()
        try:
            page.goto(url, wait_until="networkidle", timeout=self.idle_timeout_ms)
        except PlaywrightTimeout:
            pass
        except PlaywrightError:
            pass
        finally:
            context.close()
        return captured

    def capture(self, turn_id: str) -> list[dict[str, Any]]:
        return self.capture_url(f"{self.base_url}/render/{turn_id}")
