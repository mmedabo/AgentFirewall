"""Egress firewall: a default-deny filtering proxy for outbound connections.

This is the runtime "egress filtering" layer. Where the static scanner asks *does
this artifact look like it exfiltrates data?*, the egress firewall enforces *this
process may only talk to hosts on the allowlist* -- at run time, for real, even if
the payload is one no static rule recognised.

:class:`EgressPolicy` is a default-deny host/port allowlist (with wildcard
domains). :class:`EgressProxy` is a small threaded HTTP/HTTPS proxy that consults
the policy on every ``CONNECT`` tunnel and absolute-URI HTTP request, forwarding
allowed traffic and returning ``403`` for the rest, while recording every attempt.

Enforcement scope (be honest): proxy-based egress control governs any client that
honours ``HTTP(S)_PROXY`` -- which is most HTTP libraries and CLIs. A process that
deliberately opens raw sockets and ignores the proxy env is not contained by this
layer alone; combine it with OS network-namespace isolation (see sandbox.py's
``--isolate``) for bypass resistance.
"""
from __future__ import annotations

import os
import select
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Optional

_LOOPBACK = {"localhost", "127.0.0.1", "::1"}


@dataclass
class EgressPolicy:
    """A default-deny allowlist for outbound destinations."""

    #: Exact hosts or ``*.suffix`` wildcard domains that are permitted.
    allow_hosts: set[str] = field(default_factory=set)
    #: Ports that are permitted. Empty == any port for an allowed host.
    allow_ports: set[int] = field(default_factory=set)
    #: If True, loopback destinations are always allowed.
    allow_loopback: bool = False
    #: Default action when nothing matches.
    default_deny: bool = True

    @classmethod
    def from_spec(cls, hosts: list[str], ports: Optional[list[int]] = None,
                  allow_loopback: bool = False) -> "EgressPolicy":
        return cls(allow_hosts={h.strip().lower() for h in hosts if h.strip()},
                   allow_ports=set(ports or []), allow_loopback=allow_loopback)

    def allows(self, host: str, port: int) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if self.allow_loopback and host in _LOOPBACK:
            return True
        if self.allow_ports and port not in self.allow_ports:
            return False
        for rule in self.allow_hosts:
            if rule == host:
                return True
            if rule.startswith("*.") and (host == rule[2:] or host.endswith(rule[1:])):
                return True
        return not self.default_deny


@dataclass
class ConnectionAttempt:
    """One outbound connection the proxy saw, and what it decided."""

    host: str
    port: int
    method: str        # "CONNECT" (https) or "HTTP"
    allowed: bool
    timestamp: float = field(default_factory=time.time)

    def __str__(self) -> str:
        verdict = "ALLOW" if self.allowed else "BLOCK"
        return f"{verdict:5} {self.method:7} {self.host}:{self.port}"


class EgressProxy:
    """A threaded, filtering forward proxy.

    Binds to loopback TCP by default. Pass ``unix_path`` to instead listen on a
    Unix domain socket -- which, unlike TCP, is reachable across a network
    namespace boundary, making it the bridge for bypass-proof allowlisting
    (see :func:`agentfirewall.runtime.isolation.run_allowlisted`).
    """

    def __init__(self, policy: EgressPolicy, unix_path: Optional[str] = None):
        self.policy = policy
        self.unix_path = unix_path
        self.log: list[ConnectionAttempt] = []
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.address: tuple[str, int] = ("127.0.0.1", 0)

    # ---- lifecycle ------------------------------------------------------- #
    def start(self) -> tuple[str, int]:
        if self.unix_path:
            srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            if os.path.exists(self.unix_path):
                os.unlink(self.unix_path)
            srv.bind(self.unix_path)
        else:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind(("127.0.0.1", 0))
        srv.listen(64)
        srv.settimeout(0.5)
        self._server = srv
        if not self.unix_path:
            self.address = srv.getsockname()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self.address

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        if self.unix_path and os.path.exists(self.unix_path):
            try:
                os.unlink(self.unix_path)
            except OSError:
                pass

    @property
    def proxy_url(self) -> str:
        return f"http://{self.address[0]}:{self.address[1]}"

    def blocked(self) -> list[ConnectionAttempt]:
        return [a for a in self.log if not a.allowed]

    def __enter__(self) -> "EgressProxy":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()

    # ---- server loop ----------------------------------------------------- #
    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()  # type: ignore[union-attr]
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _record(self, attempt: ConnectionAttempt) -> None:
        with self._lock:
            self.log.append(attempt)

    def _handle(self, client: socket.socket) -> None:
        try:
            client.settimeout(10)
            header = _read_headers(client)
            if not header:
                return
            request_line = header.split("\r\n", 1)[0]
            parts = request_line.split(" ")
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]
            if method.upper() == "CONNECT":
                self._handle_connect(client, target)
            else:
                self._handle_http(client, method, target, header)
        except (OSError, ValueError):
            pass
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _handle_connect(self, client: socket.socket, target: str) -> None:
        host, _, port_s = target.partition(":")
        port = int(port_s or 443)
        allowed = self.policy.allows(host, port)
        self._record(ConnectionAttempt(host, port, "CONNECT", allowed))
        if not allowed:
            client.sendall(_forbidden(host, port))
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        _tunnel(client, upstream)

    def _handle_http(self, client: socket.socket, method: str, target: str,
                     header: str) -> None:
        host, port, path = _parse_absolute(target)
        if host is None:
            client.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            return
        allowed = self.policy.allows(host, port)
        self._record(ConnectionAttempt(host, port, "HTTP", allowed))
        if not allowed:
            client.sendall(_forbidden(host, port))
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError:
            client.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            return
        # Rewrite the request line to origin-form and forward headers+body.
        rest = header.split("\r\n", 1)[1] if "\r\n" in header else ""
        rewritten = f"{method} {path} HTTP/1.1\r\n{rest}".encode("latin-1", "replace")
        try:
            upstream.sendall(rewritten)
            _tunnel(client, upstream)
        finally:
            upstream.close()


# --------------------------------------------------------------------------- #
# Socket helpers
# --------------------------------------------------------------------------- #
def _read_headers(sock: socket.socket, limit: int = 65536) -> str:
    data = b""
    while b"\r\n\r\n" not in data and len(data) < limit:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data.decode("latin-1", "replace")


def _parse_absolute(target: str) -> tuple[Optional[str], int, str]:
    if "://" in target:
        scheme, _, rest = target.partition("://")
    else:
        scheme, rest = "http", target
    authority, slash, path_rest = rest.partition("/")
    host, _, port_s = authority.partition(":")
    if not host:
        return None, 0, "/"
    port = int(port_s) if port_s else (443 if scheme == "https" else 80)
    path = ("/" + path_rest) if slash else "/"
    return host, port, path


def _tunnel(a: socket.socket, b: socket.socket) -> None:
    """Relay bytes between two sockets until either closes."""
    sockets = [a, b]
    a.setblocking(False)
    b.setblocking(False)
    while True:
        try:
            readable, _, err = select.select(sockets, [], sockets, 30)
        except (OSError, ValueError):
            break
        if err or not readable:
            break
        for s in readable:
            other = b if s is a else a
            try:
                data = s.recv(65536)
            except (BlockingIOError, InterruptedError):
                continue
            except OSError:
                return
            if not data:
                return
            try:
                other.sendall(data)
            except OSError:
                return


def _forbidden(host: str, port: int) -> bytes:
    body = (f"AgentFirewall egress firewall blocked a connection to "
            f"{host}:{port} (not on the allowlist).").encode()
    return (b"HTTP/1.1 403 Forbidden\r\n"
            b"Content-Type: text/plain\r\n"
            b"Connection: close\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"\r\n" + body)
