"""A zero-dependency local web UI for AgentFirewall (``afw serve``).

Wraps the exact same :class:`~agentfirewall.scanner.Scanner` the CLI uses in a
small stdlib HTTP server so a person can drag-drop a skill folder or ``.zip`` in
their browser and read the verdict, trust tier and findings without touching a
terminal. No web framework, no external assets -- it installs and runs anywhere
Python does.

Security posture (this server *is* a security tool, so it holds itself to the
bar it enforces):

* Binds to ``127.0.0.1`` by default; binding elsewhere prints a warning.
* The JSON API requires a per-run random **token**, injected into the page it
  serves, so another site open in the same browser cannot drive it.
* Uploaded files are written under a fresh temp dir with **path-traversal-safe**
  relative paths, scanned, then deleted. The scanner only reads; it never
  executes what it inspects.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import tempfile
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional

from .. import __version__
from ..intel import ThreatIntel
from ..policy import Policy
from ..scanner import Scanner

_INDEX_PATH = os.path.join(os.path.dirname(__file__), "index.html")
_MAX_UPLOAD_BYTES = 25 * 1024 * 1024  # generous cap for a folder of skills


# --------------------------------------------------------------------------- #
# Core scan entry point (shared by API + tests)
# --------------------------------------------------------------------------- #
def scan_payload(data: dict) -> dict:
    """Run a scan described by an API payload and return ``ScanResult`` JSON."""
    policy = Policy.strict() if data.get("strict") else Policy.default()
    intel = None if data.get("intel") is False else ThreatIntel.default()
    scanner = Scanner(policy=policy, intel=intel)

    path = data.get("path")
    if path:
        result = scanner.scan_path(str(path))
        return result.to_dict()

    files = data.get("files") or []
    tmp = tempfile.mkdtemp(prefix="afw-web-")
    try:
        total = 0
        for entry in files:
            rel = _safe_rel(str(entry.get("path", "")))
            if not rel:
                continue
            raw = base64.b64decode(entry.get("b64", "") or "")
            total += len(raw)
            if total > _MAX_UPLOAD_BYTES:
                raise ValueError("upload exceeds size limit")
            dest = os.path.join(tmp, rel)
            os.makedirs(os.path.dirname(dest) or tmp, exist_ok=True)
            with open(dest, "wb") as fh:
                fh.write(raw)
        result = scanner.scan_path(tmp)
        result.artifact.name = str(data.get("name") or "uploaded-artifact")
        result.artifact.root = ""  # don't leak the temp path to the browser
        return result.to_dict()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _safe_rel(rel: str) -> str:
    """Normalize a browser-supplied path to a safe, in-sandbox relative path."""
    rel = rel.replace("\\", "/")
    parts = []
    for part in rel.split("/"):
        if part in ("", ".", ".."):
            continue
        parts.append(part)
    return os.path.join(*parts) if parts else ""


def rules_payload() -> list[dict]:
    from ..rules import all_rules
    from ..rules.base import PatternRule

    rows: list[dict] = []
    for rule in all_rules():
        if isinstance(rule, PatternRule):
            for sig in rule.signatures:
                rows.append({"id": sig.id, "severity": sig.severity.label,
                             "category": rule.category, "title": sig.title,
                             "references": list(sig.references or rule.default_references)})
        else:
            rows.append({"id": rule.id + "-*", "severity": "varies",
                         "category": rule.category, "title": type(rule).__name__,
                         "references": []})
    return rows


# --------------------------------------------------------------------------- #
# HTTP handler
# --------------------------------------------------------------------------- #
def make_handler(token: str):
    with open(_INDEX_PATH, "r", encoding="utf-8") as fh:
        index_html = fh.read().replace("{{TOKEN}}", token).replace("{{VERSION}}", __version__)
    index_bytes = index_html.encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        server_version = f"AgentFirewall/{__version__}"

        def log_message(self, *args):  # keep the console quiet
            pass

        # -- helpers --
        def _send(self, code: int, body: bytes, ctype: str) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def _json(self, code: int, obj) -> None:
            self._send(code, json.dumps(obj).encode("utf-8"), "application/json")

        def _authed(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-AFW-Token", ""), token)

        # -- routes --
        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path in ("/", "/index.html"):
                self._send(200, index_bytes, "text/html; charset=utf-8")
            elif path == "/api/rules":
                if not self._authed():
                    self._json(403, {"error": "invalid token"})
                    return
                self._json(200, {"version": __version__, "rules": rules_payload()})
            else:
                self._send(404, b"not found", "text/plain")

        def do_POST(self) -> None:
            path = self.path.split("?", 1)[0]
            if path != "/api/scan":
                self._send(404, b"not found", "text/plain")
                return
            if not self._authed():
                self._json(403, {"error": "invalid token"})
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length > _MAX_UPLOAD_BYTES:
                self._json(413, {"error": "payload too large"})
                return
            try:
                data = json.loads(self.rfile.read(length) or b"{}")
                result = scan_payload(data)
            except Exception as exc:  # surface errors to the UI rather than 500-crash
                self._json(400, {"error": f"{type(exc).__name__}: {exc}"})
                return
            self._json(200, result)

    return Handler


# --------------------------------------------------------------------------- #
# Server entry point
# --------------------------------------------------------------------------- #
def serve(host: str = "127.0.0.1", port: int = 8000, open_browser: bool = False,
          token: Optional[str] = None) -> None:
    token = token or secrets.token_urlsafe(16)
    httpd = ThreadingHTTPServer((host, port), make_handler(token))
    actual_port = httpd.server_address[1]
    url = f"http://{host}:{actual_port}/"

    print(f"AgentFirewall {__version__} — web UI")
    print(f"  ▶ {url}")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("  ⚠ bound to a non-loopback address; anyone who can reach this host "
              "can use the scanner.")
    print("  Press Ctrl-C to stop.")

    if open_browser:
        threading.Thread(target=lambda: webbrowser.open(url), daemon=True).start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        httpd.server_close()
