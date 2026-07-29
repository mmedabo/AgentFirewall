"""AgentFirewall -- a security firewall for AI agents, skills and MCP servers.

Scan agent artifacts before you install them and block anything that tries to
steal secrets, phone home, hide instructions, or run destructive commands.
"""
from __future__ import annotations

from .models import Artifact, Finding, ScannedFile, ScanResult, Severity, Verdict
from .policy import Policy
from .scanner import Scanner

__version__ = "0.5.0"

__all__ = [
    "Scanner",
    "Policy",
    "Artifact",
    "Finding",
    "ScannedFile",
    "ScanResult",
    "Severity",
    "Verdict",
    "__version__",
]
