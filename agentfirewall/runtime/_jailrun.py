"""In-jail supervisor for bypass-proof allowlisting (run inside the netns).

Launched as ``python -m agentfirewall.runtime._jailrun --sock <uds> -- <cmd>``
inside a ``unshare --net`` network namespace that has *no* IP connectivity. It:

1. brings loopback up,
2. starts a tiny TCP forwarder on ``127.0.0.1`` that relays every connection to
   the parent's Unix-domain-socket egress broker (a UDS reaches across the netns
   boundary because it is filesystem-based, not IP-based),
3. points ``HTTP(S)_PROXY`` at that forwarder, and
4. runs the target command and exits with its status.

Because the namespace has no route to anything, a process that ignores the proxy
and opens a raw socket simply gets no network -- so the broker's allowlist is the
*only* way out. That is what makes the allowlist bypass-proof.
"""
from __future__ import annotations

import os
import socket
import struct
import subprocess
import sys
import threading


def _bring_up_loopback() -> None:
    try:
        import fcntl

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        ifr = struct.pack("16sh", b"lo", 0)
        flags = struct.unpack("16sh", fcntl.ioctl(s, 0x8913, ifr))[1]  # SIOCGIFFLAGS
        fcntl.ioctl(s, 0x8914, struct.pack("16sh", b"lo", flags | 0x1))  # SIOCSIFFLAGS
        s.close()
    except Exception:
        pass


def _relay(a: socket.socket, b: socket.socket) -> None:
    import select

    a.setblocking(False)
    b.setblocking(False)
    socks = [a, b]
    while True:
        try:
            r, _, e = select.select(socks, [], socks, 30)
        except (OSError, ValueError):
            break
        if e or not r:
            break
        for s in r:
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


def _serve_forwarder(listener: socket.socket, unix_path: str, stop: threading.Event) -> None:
    listener.settimeout(0.5)
    while not stop.is_set():
        try:
            client, _ = listener.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        threading.Thread(target=_handle, args=(client, unix_path), daemon=True).start()


def _handle(client: socket.socket, unix_path: str) -> None:
    try:
        upstream = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        upstream.connect(unix_path)
    except OSError:
        try:
            client.close()
        except OSError:
            pass
        return
    try:
        _relay(client, upstream)
    finally:
        for s in (client, upstream):
            try:
                s.close()
            except OSError:
                pass


def main(argv: list[str]) -> int:
    if "--" not in argv:
        print("_jailrun: missing -- <command>", file=sys.stderr)
        return 2
    opts = argv[: argv.index("--")]
    command = argv[argv.index("--") + 1:]
    unix_path = ""
    for i, o in enumerate(opts):
        if o == "--sock" and i + 1 < len(opts):
            unix_path = opts[i + 1]
    if not unix_path or not command:
        print("_jailrun: usage --sock <uds> -- <command>", file=sys.stderr)
        return 2

    _bring_up_loopback()

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    port = listener.getsockname()[1]
    stop = threading.Event()
    threading.Thread(target=_serve_forwarder, args=(listener, unix_path, stop),
                     daemon=True).start()

    env = dict(os.environ)
    proxy = f"http://127.0.0.1:{port}"
    for key in ("HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy",
                "ALL_PROXY", "all_proxy"):
        env[key] = proxy
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""

    try:
        proc = subprocess.run(command, env=env)
        code = proc.returncode
    except FileNotFoundError:
        code = 127
    finally:
        stop.set()
        try:
            listener.close()
        except OSError:
            pass
    return code


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
