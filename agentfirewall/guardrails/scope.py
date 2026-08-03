"""Scope confinement for a deployed agent (runtime guardrail).

`InputGuard` enforces, at request time, that an agent stays inside its business
purpose: it rejects prompt-injection in user input and denies tool calls that fall
outside an allowlist or that run code/shell. It reuses the same rule engine the
scanner uses, so runtime enforcement and static detection agree.

This is the enforcement counterpart to the ``AFW-AGENCY-*`` static checks: the
scanner tells you a food-ordering bot *can* run Python; ``InputGuard`` (with a tool
allowlist) makes sure it *won't* at run time.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Optional

from ..models import Artifact, Finding, ScannedFile, Severity
from ..rules.signatures import NETWORK, OBFUSCATION, SECRETS
from ..rules.structural import HiddenUnicodeRule, PromptInjectionRule

#: Tool names that execute code/shell — denied for user-facing agents by default.
_CODE_EXEC_TOOLS = {
    "run_python", "execute_code", "python_repl", "code_interpreter", "eval_code",
    "run_code", "exec_shell", "shell_exec", "run_shell", "run_command",
    "shell", "bash", "exec", "eval", "system", "os_system", "subprocess",
}

#: Sensitive sinks that untrusted ("tainted") data must not reach — the CaMeL
#: idea that data from untrusted sources should not drive consequential actions.
_SENSITIVE_SINKS = _CODE_EXEC_TOOLS | {
    "send", "send_email", "email", "sendmail", "http_request", "httprequest",
    "fetch", "post", "request", "sql", "query", "execute_sql", "run_sql",
    "db_query", "write_file", "writefile", "delete", "delete_file", "transfer",
    "transfer_money", "pay", "payment", "checkout", "browse", "open_url",
    "webhook", "upload",
}


class Tainted(str):
    """A string marked as derived from untrusted content.

    Wrap data that comes from outside the trust boundary — tool outputs, retrieved
    documents, web pages, other agents' messages — so a :class:`ScopePolicy` can
    refuse to let it drive a sensitive tool call (indirect prompt-injection defense).
    """

    __slots__ = ()


def taint(value: Any) -> Tainted:
    """Mark ``value`` as untrusted-derived."""
    return value if isinstance(value, Tainted) else Tainted(str(value))


def _has_taint(value: Any) -> bool:
    if isinstance(value, Tainted):
        return True
    if isinstance(value, dict):
        return any(_has_taint(v) for v in value.values())
    if isinstance(value, (list, tuple, set)):
        return any(_has_taint(v) for v in value)
    return False


class GuardrailBlocked(Exception):
    """Raised when a guardrail denies a request."""

    def __init__(self, reason: str, findings: Optional[list[Finding]] = None):
        super().__init__(reason)
        self.reason = reason
        self.findings = findings or []


@dataclass
class GuardDecision:
    """The outcome of a guardrail check."""

    allowed: bool
    reason: str = "ok"
    findings: list[Finding] = field(default_factory=list)

    def __bool__(self) -> bool:
        return self.allowed

    def raise_if_blocked(self) -> "GuardDecision":
        if not self.allowed:
            raise GuardrailBlocked(self.reason, self.findings)
        return self


@dataclass
class ScopePolicy:
    """What a deployed agent is allowed to do."""

    #: If set, only these tool names may be called (capability allowlist).
    allowed_tools: Optional[set[str]] = None
    #: Tool names that are always denied (in addition to code-exec tools).
    denied_tools: set[str] = field(default_factory=set)
    #: Deny tool calls that run code/shell, and code/obfuscation in input.
    deny_code_execution: bool = True
    #: Deny inputs containing prompt-injection.
    deny_prompt_injection: bool = True
    #: Findings at or above this severity block.
    block_severity: Severity = Severity.HIGH
    #: Optional hard cap on user input length.
    max_input_chars: Optional[int] = None
    #: Refuse tool calls that carry tainted (untrusted-derived) data into a
    #: sensitive sink — the CaMeL-style defense against indirect prompt injection.
    taint_sensitive_sinks: bool = True
    #: Tool names tainted data may not reach. ``None`` == the built-in sink set.
    deny_tainted_to: Optional[set[str]] = None

    @classmethod
    def for_tools(cls, *tools: str, **kwargs: Any) -> "ScopePolicy":
        """Confine the agent to exactly ``tools`` (plus the default denials)."""
        return cls(allowed_tools={t.lower() for t in tools}, **kwargs)


class InputGuard:
    """Runtime scope enforcement for user input and tool calls."""

    def __init__(self, policy: Optional[ScopePolicy] = None):
        self.policy = policy or ScopePolicy()
        self._input_rules = [PromptInjectionRule(), HiddenUnicodeRule(), OBFUSCATION]
        self._arg_rules = [PromptInjectionRule(), OBFUSCATION, SECRETS, NETWORK]

    # ---- user input ------------------------------------------------------ #
    def check_input(self, text: str) -> GuardDecision:
        p = self.policy
        if p.max_input_chars is not None and len(text) > p.max_input_chars:
            return GuardDecision(False, f"input exceeds {p.max_input_chars} characters")
        findings = _scan(text, "doc", self._input_rules)
        if p.deny_prompt_injection:
            inj = [f for f in findings if f.category == "prompt-injection"]
            if inj:
                return GuardDecision(False, "prompt injection detected in input", inj)
        if p.deny_code_execution:
            code = [f for f in findings
                    if f.category == "obfuscation" and f.severity >= p.block_severity]
            if code:
                return GuardDecision(False, "code execution / obfuscation in input", code)
        severe = [f for f in findings if f.severity >= p.block_severity]
        if severe:
            return GuardDecision(False, f"input blocked ({severe[0].title})", severe)
        return GuardDecision(True, "ok", findings)

    # ---- tool calls ------------------------------------------------------ #
    def check_tool_call(self, name: str, arguments: Any = "",
                        tainted: Optional[bool] = None) -> GuardDecision:
        """Decide whether the agent may call ``name`` with ``arguments``.

        ``tainted`` marks the call as carrying untrusted-derived data; if omitted,
        taint is inferred from :class:`Tainted` values inside ``arguments``.
        """
        p = self.policy
        low = name.strip().lower()
        base = low.split("(", 1)[0]
        if p.deny_code_execution and (low in _CODE_EXEC_TOOLS or base in _CODE_EXEC_TOOLS):
            return GuardDecision(False, f"tool '{name}' runs code and is denied by scope policy")
        if low in {t.lower() for t in p.denied_tools}:
            return GuardDecision(False, f"tool '{name}' is explicitly denied")
        if p.allowed_tools is not None and low not in p.allowed_tools:
            return GuardDecision(
                False, f"tool '{name}' is not in the allowed set "
                f"{sorted(p.allowed_tools)}")

        # Taint / provenance gate: untrusted-derived data must not drive a
        # sensitive tool (CaMeL-style indirect-prompt-injection defense).
        is_tainted = _has_taint(arguments) if tainted is None else tainted
        if is_tainted:
            sinks = ({t.lower() for t in p.deny_tainted_to}
                     if p.deny_tainted_to is not None
                     else (_SENSITIVE_SINKS if p.taint_sensitive_sinks else set()))
            if low in sinks or base in sinks:
                return GuardDecision(
                    False, f"tool '{name}' may not receive tainted (untrusted-derived) "
                    "data — indirect prompt-injection risk")

        arg_text = arguments if isinstance(arguments, str) else _to_text(arguments)
        findings = _scan(arg_text, "script", self._arg_rules) if arg_text else []
        severe = [f for f in findings if f.severity >= p.block_severity]
        if severe:
            return GuardDecision(False, f"tool arguments blocked ({severe[0].title})", severe)
        return GuardDecision(True, "ok", findings)


def _scan(text: str, role: str, rules: list) -> list[Finding]:
    if not text:
        return []
    art = Artifact(name="request", root="", kind="request",
                   files=[ScannedFile(path="<input>", text=text, role=role)], metadata={})
    out: list[Finding] = []
    for rule in rules:
        out.extend(rule.check(art))
    return out


def _to_text(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(value)
