"""Tests for the third digest batch: ASI07 inter-agent (A2A), outbound DLP."""
import http.server
import os
import socket
import socketserver
import threading

import pytest

from agentfirewall import Scanner
from agentfirewall.models import Artifact, ScannedFile
from agentfirewall.rules.signatures import INTER_AGENT
from agentfirewall.runtime.egress import EgressPolicy, EgressProxy

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


# ------------------------------ E. ASI07 A2A ------------------------------- #
def _a2a_ids(text, path="agent.json"):
    art = Artifact(name="t", root="", kind="mcp",
                   files=[ScannedFile(path, text, role="manifest")], metadata={})
    return {f.rule_id for f in INTER_AGENT.check(art)}


def test_agent_card_without_auth_flagged():
    card = '{"skills":[{"id":"refund"}],"capabilities":{"streaming":true},"authentication":{"schemes":[]}}'
    assert "AFW-A2A-001" in _a2a_ids(card)


def test_verification_disabled_flagged():
    assert "AFW-A2A-002" in _a2a_ids("register_agent(card, verify_signature=False)\n", "reg.py")


def test_trust_all_agents_flagged():
    assert "AFW-A2A-002" in _a2a_ids("cfg = dict(trust_all_agents=True)\n", "reg.py")


def test_authenticated_card_not_flagged():
    card = ('{"skills":[{"id":"refund"}],"capabilities":{"streaming":true},'
            '"authentication":{"schemes":["oauth2"]}}')
    assert "AFW-A2A-001" not in _a2a_ids(card)


def test_insecure_a2a_example_blocks():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "insecure-a2a"))
    ids = {f.rule_id for f in result.findings}
    assert {"AFW-A2A-001", "AFW-A2A-002"} <= ids
    refs = {r for f in result.findings for r in f.references}
    assert any(r.startswith("OWASP-ASI07") for r in refs)


# ------------------------------ D. outbound DLP ---------------------------- #
@pytest.fixture
def echo_server():
    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(n)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _proxy_post(addr, url, body):
    s = socket.create_connection(addr, timeout=5)
    req = (f"POST {url} HTTP/1.1\r\nHost: t\r\nContent-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n{body}")
    s.sendall(req.encode())
    buf = b""
    while True:
        d = s.recv(4096)
        if not d:
            break
        buf += d
    s.close()
    return buf.decode("latin-1")


def test_dlp_blocks_secret_in_body(echo_server):
    with EgressProxy(EgressPolicy.from_spec([], allow_loopback=True)) as p:
        resp = _proxy_post(p.address, f"http://127.0.0.1:{echo_server}/x", "k=ghp_" + "a" * 36)
        assert "403 Forbidden" in resp
        assert p.blocked() and p.blocked()[0].method == "HTTP-DLP"


def test_dlp_allows_clean_body(echo_server):
    with EgressProxy(EgressPolicy.from_spec([], allow_loopback=True)) as p:
        resp = _proxy_post(p.address, f"http://127.0.0.1:{echo_server}/x", "hello=world")
        assert "200 OK" in resp
        assert not p.blocked()


def test_dlp_can_be_disabled(echo_server):
    policy = EgressPolicy.from_spec([], allow_loopback=True)
    policy.dlp_scan_bodies = False
    with EgressProxy(policy) as p:
        resp = _proxy_post(p.address, f"http://127.0.0.1:{echo_server}/x", "k=ghp_" + "a" * 36)
        assert "200 OK" in resp  # secret forwarded when DLP off
