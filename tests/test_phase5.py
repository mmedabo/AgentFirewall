"""Tests for bypass-proof network isolation (Phase 5).

The live-namespace tests are skipped where the host can't create a network
namespace (CI without the capability, non-Linux); the argv-builder and refusal
tests always run.
"""
import os

import pytest

from agentfirewall.cli import main
from agentfirewall.runtime import isolation

_ISO = isolation.probe()
_needs_ns = pytest.mark.skipif(not _ISO.available,
                               reason=f"no network isolation available: {_ISO.notes}")


# ------------------------------- always run -------------------------------- #
def test_probe_returns_isolation():
    iso = isolation.probe()
    assert isinstance(iso, isolation.Isolation)
    assert iso.available in (True, False)
    if iso.available:
        assert iso.backend in ("unshare", "bwrap")


def test_run_isolated_refuses_when_unavailable():
    unavailable = isolation.Isolation(False, None, None, ["forced for test"])
    with pytest.raises(isolation.IsolationUnavailable):
        isolation.run_isolated(["true"], isolation=unavailable)


def test_build_argv_unshare_denies_network():
    iso = isolation.Isolation(True, "unshare", "unshare (root netns)", [])
    argv = isolation._build_argv(iso, ["echo", "hi"], up_loopback=False)
    assert argv[0] == "unshare"
    assert "--net" in argv
    assert argv[-2:] == ["echo", "hi"]


def test_build_argv_bwrap_unshares_net():
    iso = isolation.Isolation(True, "bwrap", "bubblewrap", [])
    argv = isolation._build_argv(iso, ["echo", "hi"], up_loopback=True)
    assert argv[0] == "bwrap"
    assert "--unshare-net" in argv
    assert argv[-2:] == ["echo", "hi"]


def test_build_argv_loopback_uses_bootstrap():
    iso = isolation.Isolation(True, "unshare", "unshare (root netns)", [])
    argv = isolation._build_argv(iso, ["mytool", "--x"], up_loopback=True)
    assert "-c" in argv                      # python bootstrap
    assert argv[-2:] == ["mytool", "--x"]


# ------------------------------- needs a namespace ------------------------- #
@_needs_ns
def test_isolated_child_cannot_reach_network():
    child = ("import socket,sys\n"
             "try:\n"
             " socket.create_connection(('1.1.1.1',53),timeout=3); sys.exit(9)\n"
             "except OSError: sys.exit(0)\n")
    result = isolation.run_isolated(["python3", "-c", child], timeout=20)
    assert result.exit_code == 0          # connection was refused inside the jail
    assert result.network == "none"


@_needs_ns
def test_isolated_exit_code_passthrough():
    result = isolation.run_isolated(["python3", "-c", "import sys; sys.exit(7)"], timeout=20)
    assert result.exit_code == 7


@_needs_ns
def test_isolated_loopback_works():
    prog = ("import socket,threading\n"
            "srv=socket.socket(); srv.bind(('127.0.0.1',0)); srv.listen(1)\n"
            "p=srv.getsockname()[1]\n"
            "def acc():\n c,_=srv.accept(); c.send(b'ok'); c.close()\n"
            "threading.Thread(target=acc,daemon=True).start()\n"
            "c=socket.create_connection(('127.0.0.1',p),timeout=3)\n"
            "import sys; sys.exit(0 if c.recv(2)==b'ok' else 1)\n")
    result = isolation.run_isolated(["python3", "-c", prog], timeout=20)
    assert result.exit_code == 0


# ------------------------------- CLI --------------------------------------- #
@_needs_ns
def test_cli_isolate_allow_is_allowlist_mode():
    # --isolate + --allow is now bypass-proof allowlisting (Phase 5.5), not an error.
    # Running `true` needs no network, so it succeeds inside the jail.
    assert main(["run", "--isolate", "--allow", "x.example", "--", "true"]) == 0


def test_cli_run_no_command_errors():
    assert main(["run", "--isolate"]) == 1


@_needs_ns
def test_cli_isolate_blocks_network():
    child = ("import socket,sys\n"
             "try:\n"
             " socket.create_connection(('1.1.1.1',53),timeout=3); sys.exit(9)\n"
             "except OSError: sys.exit(0)\n")
    assert main(["run", "--isolate", "--", "python3", "-c", child]) == 0
