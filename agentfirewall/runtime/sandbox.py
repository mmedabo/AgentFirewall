"""Run a command behind the egress firewall (``afw run``).

Wires a child process's outbound HTTP(S) through :class:`EgressProxy` with a
default-deny allowlist, then reports every destination it tried to reach and which
were blocked. This is the practical, cross-platform egress control: it governs any
client that honours ``HTTP(S)_PROXY`` (most HTTP libraries and CLIs).

Honesty note: a process that opens raw sockets and ignores the proxy environment
is not contained by proxy-env enforcement alone. OS-level network-namespace
isolation would make it bypass-proof; that hardening is tracked for a later
iteration. Even so, default-deny egress for proxy-respecting agents/tools stops
the overwhelming majority of real-world exfiltration paths.
"""
from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass, field
from typing import Optional

from .egress import ConnectionAttempt, EgressPolicy, EgressProxy

_PROXY_ENV_KEYS = (
    "HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
    "ALL_PROXY", "all_proxy",
)


@dataclass
class SessionReport:
    """What happened while a command ran behind the egress firewall."""

    command: list[str]
    exit_code: int
    attempts: list[ConnectionAttempt] = field(default_factory=list)

    def blocked(self) -> list[ConnectionAttempt]:
        return [a for a in self.attempts if not a.allowed]

    def allowed(self) -> list[ConnectionAttempt]:
        return [a for a in self.attempts if a.allowed]

    def to_dict(self) -> dict:
        return {
            "command": self.command,
            "exit_code": self.exit_code,
            "egress": {
                "allowed": [str(a) for a in self.allowed()],
                "blocked": [str(a) for a in self.blocked()],
                "total": len(self.attempts),
            },
        }


def run_guarded(command: list[str], policy: EgressPolicy,
                env: Optional[dict] = None, timeout: Optional[float] = None,
                cwd: Optional[str] = None) -> SessionReport:
    """Run ``command`` with outbound traffic filtered by ``policy``."""
    proxy = EgressProxy(policy)
    proxy.start()
    child_env = dict(os.environ if env is None else env)
    for key in _PROXY_ENV_KEYS:
        child_env[key] = proxy.proxy_url
    # Ensure the child does not bypass the proxy via a pre-existing no_proxy.
    child_env["NO_PROXY"] = ""
    child_env["no_proxy"] = ""

    exit_code = 0
    try:
        proc = subprocess.run(command, env=child_env, cwd=cwd, timeout=timeout)
        exit_code = proc.returncode
    except FileNotFoundError:
        exit_code = 127
    except subprocess.TimeoutExpired:
        exit_code = 124
    finally:
        time.sleep(0.15)  # let any in-flight attempts finish recording
        proxy.stop()

    return SessionReport(command=command, exit_code=exit_code, attempts=list(proxy.log))
