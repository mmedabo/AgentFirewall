"""Tests for the local web UI (afw serve)."""
import base64
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from agentfirewall.web.server import _safe_rel, make_handler, rules_payload, scan_payload

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def _upload(path):
    files = []
    for root, _, names in os.walk(path):
        for n in names:
            full = os.path.join(root, n)
            rel = os.path.relpath(full, path)
            files.append({"path": rel, "b64": base64.b64encode(open(full, "rb").read()).decode()})
    return files


# ------------------------------- scan_payload ------------------------------ #
def test_scan_payload_upload_malicious_blocks():
    res = scan_payload({"files": _upload(os.path.join(EXAMPLES, "malicious-skill")),
                        "name": "super-helper"})
    assert res["verdict"] == "block"
    assert res["artifact"]["name"] == "super-helper"
    assert res["artifact"]["root"] == ""  # temp path not leaked
    assert res["findings"]


def test_scan_payload_path_mode_allows_safe():
    res = scan_payload({"path": os.path.join(EXAMPLES, "safe-skill")})
    assert res["verdict"] == "allow"


def test_scan_payload_strict_flag():
    res = scan_payload({"path": os.path.join(EXAMPLES, "safe-skill"), "strict": True})
    assert res["verdict"] in ("allow", "warn", "block")  # runs without error


def test_safe_rel_blocks_traversal():
    assert _safe_rel("../../etc/passwd") == "etc/passwd"
    assert _safe_rel("/abs/x") == os.path.join("abs", "x")
    assert _safe_rel("..") == ""
    assert _safe_rel("a/./b") == os.path.join("a", "b")


def test_upload_cannot_escape_tmp(tmp_path):
    # A traversal path must not write outside the sandbox temp dir.
    marker = tmp_path / "escaped.txt"
    payload = {"files": [{"path": f"../../../../../../{marker}",
                          "b64": base64.b64encode(b"x").decode()}]}
    scan_payload(payload)
    assert not marker.exists()


def test_rules_payload_nonempty():
    rows = rules_payload()
    ids = {r["id"] for r in rows}
    assert "AFW-SEC-001" in ids


# ------------------------------- live server ------------------------------- #
@pytest.fixture
def server():
    token = "test-token-xyz"
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(token))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", token
    srv.shutdown()


def test_index_served_with_token(server):
    base, token = server
    html = urllib.request.urlopen(base + "/").read().decode()
    assert token in html and "AgentFirewall" in html
    assert "{{TOKEN}}" not in html  # template was filled


def test_api_requires_token(server):
    base, _ = server
    req = urllib.request.Request(base + "/api/scan", data=b'{"path":"x"}',
                                 headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req)
    assert ei.value.code == 403


def test_api_scan_with_token(server):
    base, token = server
    body = json.dumps({"path": os.path.join(EXAMPLES, "malicious-skill")}).encode()
    req = urllib.request.Request(base + "/api/scan", data=body,
                                 headers={"Content-Type": "application/json",
                                          "X-AFW-Token": token})
    data = json.loads(urllib.request.urlopen(req).read())
    assert data["verdict"] == "block"


def test_api_bad_json_returns_400(server):
    base, token = server
    req = urllib.request.Request(base + "/api/scan", data=b"not json",
                                 headers={"Content-Type": "application/json",
                                          "X-AFW-Token": token})
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(req)
    assert ei.value.code == 400


def test_unknown_route_404(server):
    base, _ = server
    with pytest.raises(urllib.error.HTTPError) as ei:
        urllib.request.urlopen(base + "/nope")
    assert ei.value.code == 404
