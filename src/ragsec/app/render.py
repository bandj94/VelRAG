"""Rendering support (spec §6.7).

The UI and ``/render/{turn_id}`` share one renderer module (ui/renderer.js): the
vendored markdown library converts the answer to HTML in the browser, passing
images and raw HTML through, and the result is inserted with ``innerHTML``.
Under that renderer, ``<script>`` elements never run, but event-handler
attributes do, and so do automatic loads such as images and iframes.

The render page carries the delivered answer in a ``data-answer`` attribute
(HTML-escaped), so the page itself has no inline script and still works under
D2's Content-Security-Policy.
"""

from __future__ import annotations

import html
import threading
from collections import OrderedDict

RENDER_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Vel answer</title>
<link rel="stylesheet" href="/static/style.css">
<script src="/static/vendor/marked.min.js" defer></script>
<script src="/static/renderer.js" defer></script>
<script src="/static/render-page.js" defer></script>
</head>
<body class="render-page">
<main><div id="answer" class="answer" data-answer="{answer}"></div></main>
</body>
</html>
"""


def render_page(answer: str) -> str:
    return RENDER_PAGE.replace("{answer}", html.escape(answer, quote=True))


class TurnStore:
    """Delivered answers, kept in memory for /render/{turn_id}."""

    def __init__(self, max_items: int = 20000) -> None:
        self._items: OrderedDict[str, str] = OrderedDict()
        self._lock = threading.Lock()
        self.max_items = max_items

    def put(self, turn_id: str, answer: str) -> None:
        with self._lock:
            self._items[turn_id] = answer
            while len(self._items) > self.max_items:
                self._items.popitem(last=False)

    def get(self, turn_id: str) -> str | None:
        with self._lock:
            return self._items.get(turn_id)
