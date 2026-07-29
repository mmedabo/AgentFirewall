"""Local web UI for AgentFirewall. See :mod:`agentfirewall.web.server`."""
from .server import scan_payload, serve

__all__ = ["serve", "scan_payload"]
