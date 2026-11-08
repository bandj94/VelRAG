"""The attacker's exfiltration server (spec §6.4).

Binds 127.0.0.1:8765. Logs every request (time, Host header, path, decoded
query, body) to logs/attacker.jsonl and returns a 1x1 PNG. Exfiltration URLs use
hosts like ``img.attacker.localhost:8765``, which Chromium resolves to this
machine.
"""

from __future__ import annotations

import base64
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qsl, unquote_plus, urlsplit

PIXEL = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
)


def make_server(host: str, port: int, log_path: Path) -> ThreadingHTTPServer:
    if host not in ("127.0.0.1", "localhost", "::1"):
        raise ValueError("rule 9: the attacker server binds to loopback only")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "attacker/1.0"

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            parts = urlsplit(self.path)
            entry = {
                "time": time.time(),
                "method": self.command,
                "host": self.headers.get("Host", ""),
                "path": unquote_plus(parts.path),
                "query": dict(parse_qsl(parts.query, keep_blank_values=True)),
                "raw_query": unquote_plus(parts.query),
                "body": body,
                "referer": self.headers.get("Referer", ""),
            }
            with lock, log_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(PIXEL)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(PIXEL)

        do_GET = do_POST = do_PUT = do_HEAD = do_OPTIONS = _handle  # noqa: N815

        def log_message(self, format: str, *args: object) -> None:  # silence stderr
            return

    return ThreadingHTTPServer((host, port), Handler)


def serve(host: str, port: int, log_path: Path) -> None:
    srv = make_server(host, port, log_path)
    print(f"[attacker] listening on http://{host}:{port} (logging to {log_path})", flush=True)
    srv.serve_forever()
