"""Tests for bypass-proof allowlisting (Phase 5.5).

Namespace-dependent tests are skipped where an unshare network namespace can't be
created; the UDS-proxy test needs no namespace and always runs.
"""
import http.server
import socket
import socketserver
import threading

import pytest

from agentfirewall.cli import main
from agentfirewall.runtime import isolation
from agentfirewall.runtime.egress import EgressPolicy, EgressProxy

_HAS_NS = isolation.unshare_net_prefix() is not None
_needs_ns = pytest.mark.skipif(not _HAS_NS, reason="no unshare network namespace available")


@pytest.fixture
def target_server():
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"target-ok")

        def log_message(self, *a):
            pass

    srv = socketserver.TCPServer(("127.0.0.1", 0), H)
    srv.allow_reuse_address = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


# ------------------------- UDS proxy (no namespace needed) ----------------- #
def test_egress_proxy_over_unix_socket(tmp_path, target_server):
    sock = str(tmp_path / "broker.sock")
    proxy = EgressProxy(EgressPolicy.from_spec([], allow_loopback=True), unix_path=sock)
    proxy.start()
    try:
        c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        c.connect(sock)
        c.sendall(f"GET http://127.0.0.1:{target_server}/x HTTP/1.1\r\n"
                  f"Host: t\r\nConnection: close\r\n\r\n".encode())
        buf = b""
        while True:
            d = c.recv(4096)
            if not d:
                break
            buf += d
        c.close()
        assert b"200 OK" in buf and b"target-ok" in buf
        assert proxy.log and proxy.log[0].allowed
    finally:
        proxy.stop()
    import os
    assert not os.path.exists(sock)  # cleaned up on stop


def test_unshare_prefix_shape():
    prefix = isolation.unshare_net_prefix()
    if prefix is None:
        pytest.skip("no unshare netns")
    assert prefix[0] == "unshare" and "--net" in prefix


# ------------------------- bypass-proof allowlisting ----------------------- #
@_needs_ns
def test_allowlisted_reaches_allowed_and_blocks_raw(target_server):
    child = (
        "import urllib.request, socket, sys\n"
        f"urllib.request.urlopen('http://127.0.0.1:{target_server}/x', timeout=5).read()\n"
        "try:\n"
        " socket.create_connection(('1.1.1.1',53),timeout=3); sys.exit(9)\n"  # raw bypass?
        "except OSError: pass\n"
        "sys.exit(0)\n"
    )
    policy = EgressPolicy.from_spec([], allow_loopback=True)
    report = isolation.run_allowlisted(["python3", "-c", child], policy, timeout=30)
    assert report.exit_code == 0                       # proxy reach ok, raw blocked
    assert any(a.allowed and a.port == target_server for a in report.attempts)


@_needs_ns
def test_allowlisted_blocks_non_allowlisted_host(target_server):
    # Policy allows only a bogus host; reaching the local server must be refused.
    child = (
        "import urllib.request, sys\n"
        "try:\n"
        f" urllib.request.urlopen('http://127.0.0.1:{target_server}/x', timeout=5)\n"
        " sys.exit(9)\n"
        "except Exception:\n"
        " sys.exit(0)\n"   # 403 from broker → urllib raises → expected
    )
    policy = EgressPolicy.from_spec(["nothing.example"])
    report = isolation.run_allowlisted(["python3", "-c", child], policy, timeout=30)
    assert report.exit_code == 0
    assert report.blocked()                            # broker recorded a BLOCK


@_needs_ns
def test_cli_isolate_allow_returns_zero(target_server):
    child = (f"import urllib.request; "
             f"urllib.request.urlopen('http://127.0.0.1:{target_server}/x', timeout=5).read()")
    rc = main(["run", "--isolate", "--allow-loopback", "--", "python3", "-c", child])
    assert rc == 0


@_needs_ns
def test_cli_isolate_allow_fail_on_egress(target_server):
    # Reach a non-allowlisted host → blocked → --fail-on-egress makes it exit 3.
    child = (f"import urllib.request\n"
             f"try: urllib.request.urlopen('http://127.0.0.1:{target_server}/x', timeout=5)\n"
             f"except Exception: pass\n")
    rc = main(["run", "--isolate", "--allow", "nothing.example", "--fail-on-egress",
               "--", "python3", "-c", child])
    assert rc == 3
