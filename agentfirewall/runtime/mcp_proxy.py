"""MCP tool-call proxy: the application-layer (WAF) firewall.

An MCP server speaks JSON-RPC to the agent over stdio. That channel is exactly
where the dangerous data-in-motion attacks live: a ``tools/list`` response can
carry a **poisoned tool description**, a tool *result* can smuggle **injected
instructions** back into the model's context, and tool-call *arguments* can carry
**exfiltrated secrets** out. A static scan of the server's code never sees any of
this, because it only happens at run time.

:class:`McpInspector` sits in the middle like a reverse proxy in front of a web
app: it inspects every JSON-RPC message flowing each way, runs the AgentFirewall
rule engine over the security-relevant fields, and can **forward**, **redact** or
**block** the message. :func:`run_stdio_proxy` wires it between a real client and a
spawned server over stdio.

Message flow and what we inspect:

* client → server ``tools/call`` params  → secret egress, injected content
* server → client ``tools/list`` result  → tool poisoning in descriptions
* server → client tool-call result       → injected instructions, secret DLP
"""
from __future__ import annotations

import json
import subprocess
import threading
from dataclasses import dataclass, field
from typing import Any, BinaryIO, Optional

from ..models import Artifact, Finding, ScannedFile, Severity
from ..rules.signatures import EMBEDDED_SECRETS, NETWORK, SECRETS
from ..rules.structural import HiddenUnicodeRule, PromptInjectionRule, ToolPoisoningRule

Action = str  # "forward" | "redact" | "block"


@dataclass
class Decision:
    """What the proxy decided to do with one message."""

    action: Action
    message: Optional[dict]                 # possibly modified message to forward
    findings: list[Finding] = field(default_factory=list)
    error_response: Optional[dict] = None   # JSON-RPC error to return for a blocked request

    @property
    def severe(self) -> bool:
        return any(f.severity >= Severity.HIGH for f in self.findings)


class McpInspector:
    """Inspects JSON-RPC messages and decides forward / redact / block."""

    def __init__(self, action: Action = "block",
                 block_severity: Severity = Severity.HIGH):
        assert action in ("warn", "redact", "block")
        self.action = action
        self.block_severity = block_severity
        self.log: list[Finding] = []
        self._desc_rules = [ToolPoisoningRule(), PromptInjectionRule(), HiddenUnicodeRule()]
        self._data_rules = [PromptInjectionRule(), HiddenUnicodeRule(),
                            SECRETS, NETWORK, EMBEDDED_SECRETS]

    # ---- direction handlers --------------------------------------------- #
    def handle_client_to_server(self, msg: dict) -> Decision:
        findings: list[Finding] = []
        if isinstance(msg, dict) and msg.get("method") == "tools/call":
            params = msg.get("params") or {}
            name = params.get("name", "?")
            args_text = json.dumps(params.get("arguments", {}), ensure_ascii=False)
            findings = self._scan(args_text, "script", self._data_rules,
                                  where=f"tools/call({name}) arguments")
        return self._decide(msg, findings, is_request=_is_request(msg))

    def handle_server_to_client(self, msg: dict) -> Decision:
        findings: list[Finding] = []
        result = msg.get("result") if isinstance(msg, dict) else None
        if isinstance(result, dict):
            if isinstance(result.get("tools"), list):
                findings += self._scan_tools(result["tools"])
            if "content" in result:
                findings += self._scan(_content_text(result["content"]), "doc",
                                       self._data_rules, where="tool result")
        return self._decide(msg, findings, is_request=False)

    # ---- scanning helpers ----------------------------------------------- #
    def _scan_tools(self, tools: list) -> list[Finding]:
        descs = [{"name": t.get("name", "?"), "text": str(t.get("description", ""))}
                 for t in tools if isinstance(t, dict)]
        art = Artifact(name="mcp", root=".", kind="mcp", files=[],
                       metadata={"tool_descriptions": descs, "manifest_path": "tools/list"})
        out: list[Finding] = []
        for rule in self._desc_rules:
            if isinstance(rule, ToolPoisoningRule):
                out.extend(rule.check(art))
        # Also scan each description as text for injection / hidden unicode.
        for d in descs:
            out += self._scan(d["text"], "manifest", [PromptInjectionRule(),
                              HiddenUnicodeRule()], where=f"tools/list:{d['name']}")
        self.log.extend(out)
        return out

    def _scan(self, text: str, role: str, rules: list, where: str = "") -> list[Finding]:
        if not text:
            return []
        art = Artifact(name="mcp", root=".", kind="mcp",
                       files=[ScannedFile(path=where or "<stream>", text=text, role=role)],
                       metadata={})
        out: list[Finding] = []
        for rule in rules:
            out.extend(rule.check(art))
        self.log.extend(out)
        return out

    # ---- decision ------------------------------------------------------- #
    def _decide(self, msg: dict, findings: list[Finding], is_request: bool) -> Decision:
        severe = any(f.severity >= self.block_severity for f in findings)
        if not severe or self.action == "warn":
            return Decision("forward", msg, findings)

        if self.action == "block" and is_request:
            return Decision("block", None, findings,
                            error_response=_jsonrpc_error(
                                msg.get("id"),
                                "AgentFirewall blocked this tool call: "
                                "the arguments matched a security rule."))
        # Redact (or block of a response we can't drop): scrub the text fields.
        redacted = _redact_message(msg, findings)
        return Decision("redact", redacted, findings)


# --------------------------------------------------------------------------- #
# stdio relay
# --------------------------------------------------------------------------- #
def run_stdio_proxy(server_cmd: list[str], inspector: McpInspector,
                    client_in: BinaryIO, client_out: BinaryIO,
                    on_event=None) -> int:
    """Relay newline-delimited JSON-RPC between a client and a spawned server.

    ``client_in`` / ``client_out`` are the agent-facing byte streams (usually this
    process's stdin/stdout). Returns the server's exit code.
    """
    proc = subprocess.Popen(server_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    def pump(src: BinaryIO, dst: BinaryIO, handler, is_c2s: bool) -> None:
        for raw in iter(src.readline, b""):
            line = raw.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except (ValueError, json.JSONDecodeError):
                _write(dst, raw)  # pass through non-JSON untouched
                continue
            decision = handler(msg)
            if on_event:
                on_event(is_c2s, decision)
            if decision.action == "block":
                # Do not forward; answer the client with a JSON-RPC error.
                if decision.error_response is not None:
                    _write_json(client_out, decision.error_response)
                continue
            _write_json(dst, decision.message if decision.message is not None else msg)
        # Signal EOF to the server by closing its stdin; never close the
        # client-facing stream, which the caller owns.
        if is_c2s:
            try:
                dst.close()
            except OSError:
                pass

    t_up = threading.Thread(
        target=pump, args=(client_in, proc.stdin, inspector.handle_client_to_server, True),
        daemon=True)
    t_down = threading.Thread(
        target=pump, args=(proc.stdout, client_out, inspector.handle_server_to_client, False),
        daemon=True)
    t_up.start()
    t_down.start()
    proc.wait()
    t_down.join(timeout=2)
    return proc.returncode


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _is_request(msg: Any) -> bool:
    return isinstance(msg, dict) and "method" in msg and "id" in msg


def _content_text(content: Any) -> str:
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(str(item.get("text", "")))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    return str(content)


def _jsonrpc_error(msg_id: Any, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": msg_id,
            "error": {"code": -32001, "message": message}}


def _redact_message(msg: dict, findings: list[Finding]) -> dict:
    """Return a copy of ``msg`` with offending evidence blanked out."""
    blob = json.dumps(msg, ensure_ascii=False)
    for f in findings:
        if f.evidence and f.evidence in blob:
            blob = blob.replace(f.evidence, "[REDACTED-BY-AGENTFIREWALL]")
    try:
        red = json.loads(blob)
    except (ValueError, json.JSONDecodeError):  # pragma: no cover
        return msg
    red.setdefault("_agentfirewall", {})["redactions"] = len(findings)
    return red


def _write_json(dst: BinaryIO, msg: dict) -> None:
    _write(dst, (json.dumps(msg, ensure_ascii=False) + "\n").encode("utf-8"))


def _write(dst: BinaryIO, data: bytes) -> None:
    try:
        dst.write(data)
        dst.flush()
    except (OSError, ValueError):
        pass
