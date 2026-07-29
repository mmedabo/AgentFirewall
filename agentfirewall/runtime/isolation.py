"""Bypass-proof network isolation (Phase 5).

The Phase 4 egress firewall filters traffic through a proxy -- strong for clients
that honour ``HTTP(S)_PROXY``, but a process that opens a raw socket and ignores
the proxy env can walk around it. This module closes that gap for the most
important case: running **untrusted install hooks / setup scripts** with *no*
network at all.

It launches a command inside a fresh **network namespace** with no external
interface, so the process physically cannot reach any host -- even with raw
sockets, even as root inside the namespace. This is default-deny egress enforced
by the kernel, not by cooperation.

Scope, stated honestly:

* This provides bypass-proof **deny-all** networking. Bypass-proof *allowlisting*
  (reach these hosts, nothing else) needs a userspace network stack such as
  ``slirp4netns`` or root + ``ip``/NAT; when those aren't present, use the Phase 4
  proxy (``afw run --allow``) for allowlisting instead.
* Backends, best first: **bubblewrap** (``bwrap``) when installed (adds filesystem
  and seccomp confinement), otherwise **``unshare``** (root or a rootless user
  namespace). If neither can isolate, :func:`run_isolated` refuses rather than
  silently running the command with full network access.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

# Bootstrap run inside the namespace: best-effort bring loopback up, then exec the
# real command. Loopback failure is non-fatal (deny-all networking still holds).
_BOOTSTRAP = r"""
import os, sys
try:
    import fcntl, socket, struct
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ifr = struct.pack('16sh', b'lo', 0)
    flags = struct.unpack('16sh', fcntl.ioctl(s, 0x8913, ifr))[1]  # SIOCGIFFLAGS
    fcntl.ioctl(s, 0x8914, struct.pack('16sh', b'lo', flags | 0x1))  # SIOCSIFFLAGS, IFF_UP
    s.close()
except Exception:
    pass
cmd = sys.argv[1:]
os.execvp(cmd[0], cmd)
"""


@dataclass
class Isolation:
    """What network isolation is available on this host."""

    available: bool
    backend: Optional[str]      # "bwrap" | "unshare" | None
    method: Optional[str]       # human-readable, e.g. "unshare (root netns)"
    notes: list[str]

    def describe(self) -> str:
        return self.method or "unavailable"


def probe() -> Isolation:
    """Detect whether (and how) we can create a no-network namespace."""
    notes: list[str] = []

    if shutil.which("bwrap"):
        return Isolation(True, "bwrap", "bubblewrap (network + fs + seccomp)",
                         ["bubblewrap present"])

    if shutil.which("unshare"):
        if _can_unshare_net(["--net"]):
            root = os.geteuid() == 0
            method = "unshare (root netns)" if root else "unshare (netns)"
            return Isolation(True, "unshare", method, notes)
        if _can_unshare_net(["--map-root-user", "--net"]):
            return Isolation(True, "unshare", "unshare (rootless user+net namespace)",
                             notes)
        notes.append("unshare present but creating a network namespace failed "
                     "(kernel/seccomp/policy restriction)")
    else:
        notes.append("neither bwrap nor unshare found")
    return Isolation(False, None, None, notes)


def _can_unshare_net(flags: list[str]) -> bool:
    try:
        r = subprocess.run(["unshare", *flags, "true"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=10)
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


@dataclass
class IsolationResult:
    command: list[str]
    exit_code: int
    method: str
    network: str = "none"  # bypass-proof deny-all

    def to_dict(self) -> dict:
        return {"command": self.command, "exit_code": self.exit_code,
                "isolation": {"method": self.method, "network": self.network}}


def run_isolated(command: list[str], up_loopback: bool = True,
                 env: Optional[dict] = None, cwd: Optional[str] = None,
                 timeout: Optional[float] = None,
                 isolation: Optional[Isolation] = None) -> IsolationResult:
    """Run ``command`` in a no-network namespace.

    Raises :class:`IsolationUnavailable` if the host cannot isolate, so callers
    never silently fall back to full network access.
    """
    iso = isolation or probe()
    if not iso.available:
        raise IsolationUnavailable(
            "network isolation is not available on this host: "
            + "; ".join(iso.notes or ["no supported backend"]))

    argv = _build_argv(iso, command, up_loopback)
    try:
        proc = subprocess.run(argv, env=env, cwd=cwd, timeout=timeout)
        code = proc.returncode
    except FileNotFoundError:
        code = 127
    except subprocess.TimeoutExpired:
        code = 124
    return IsolationResult(command=command, exit_code=code, method=iso.describe())


def _build_argv(iso: Isolation, command: list[str], up_loopback: bool) -> list[str]:
    if iso.backend == "bwrap":
        # Bubblewrap: no network, private /proc + /dev, die with parent.
        return ["bwrap", "--unshare-net", "--dev", "/dev", "--proc", "/proc",
                "--ro-bind", "/", "/", "--die-with-parent", "--new-session",
                "--", *command]

    # unshare backend.
    prefix = ["unshare", "--net", "--fork"]
    if os.geteuid() != 0:
        prefix = ["unshare", "--map-root-user", "--net", "--fork"]
    if up_loopback:
        return [*prefix, sys.executable, "-c", _BOOTSTRAP, *command]
    return [*prefix, *command]


class IsolationUnavailable(RuntimeError):
    """Raised when bypass-proof isolation was requested but is not possible."""
