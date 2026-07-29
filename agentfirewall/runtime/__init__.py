"""Runtime firewall layer: egress filtering and MCP tool-call inspection.

These components watch an agent (or its tools) *while they run*, rather than
inspecting an artifact at rest. See :mod:`agentfirewall.runtime.egress` for the
default-deny egress proxy and :mod:`agentfirewall.runtime.mcp_proxy` for the
tool-call inspection proxy.
"""
from .egress import ConnectionAttempt, EgressPolicy, EgressProxy
from .isolation import (
    Isolation,
    IsolationUnavailable,
    probe,
    run_allowlisted,
    run_isolated,
)

__all__ = ["EgressPolicy", "EgressProxy", "ConnectionAttempt",
           "Isolation", "IsolationUnavailable", "probe", "run_isolated",
           "run_allowlisted"]
