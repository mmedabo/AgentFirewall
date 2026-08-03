"""Runtime guardrails you embed in a deployed agent.

Two enforcement primitives, the counterparts to the ``AFW-AGENCY-*`` and
``AFW-AUTHZ-*`` static detections:

* :class:`InputGuard` / :class:`ScopePolicy` — confine an agent to its purpose:
  reject prompt-injection and deny tool calls outside an allowlist or that run code.
* :class:`PreconditionGate` — authorize and atomically reserve quota *before* the
  agent runs, idempotent by request key, so a refresh/replay can't slip a request
  through (the Bolt.new exploit) and a zero-quota user can't get a free run.

Example::

    from agentfirewall.guardrails import (
        InputGuard, ScopePolicy, PreconditionGate, InMemoryQuota,
    )

    guard = InputGuard(ScopePolicy.for_tools("search_menu", "place_order"))
    gate = PreconditionGate(InMemoryQuota(balances={"user-1": 5}))

    def handle(user_id, prompt, request_id):
        guard.check_input(prompt).raise_if_blocked()          # scope
        return gate.run(user_id, lambda: agent.run(prompt),   # check-before-act
                        idempotency_key=request_id)
"""
from .gate import (
    InMemoryIdempotencyStore,
    InMemoryQuota,
    PreconditionGate,
    QuotaExceeded,
)
from .scope import (
    GuardDecision,
    GuardrailBlocked,
    InputGuard,
    ScopePolicy,
    Tainted,
    taint,
)

__all__ = [
    "InputGuard",
    "ScopePolicy",
    "GuardDecision",
    "GuardrailBlocked",
    "Tainted",
    "taint",
    "PreconditionGate",
    "InMemoryQuota",
    "InMemoryIdempotencyStore",
    "QuotaExceeded",
]
