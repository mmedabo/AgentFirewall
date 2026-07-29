"""Tests for deployed-agent guardrail detections (Phase 6).

Covers the two real-world classes the user reported:
  * excessive agency / no scoping (McDonald's "write Python" chatbot)
  * check-after-act quota enforcement (Bolt.new refresh exploit)
"""
import os

from agentfirewall import Scanner
from agentfirewall.models import Artifact, ScannedFile
from agentfirewall.rules import all_rules

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def _ids(text, role="script", path="x.py", metadata=None):
    art = Artifact(name="t", root=".", kind="unknown",
                   files=[ScannedFile(path=path, text=text, role=role)],
                   metadata=metadata or {})
    out = set()
    for rule in all_rules():
        out.update(f.rule_id for f in rule.check(art))
    return out


# ------------------------------ excessive agency -------------------------- #
def test_user_input_drives_exec():
    assert "AFW-AGENCY-001" in _ids("result = exec(request.json['prompt'])\n")


def test_code_execution_tool_exposed():
    assert "AFW-AGENCY-002" in _ids('@tool("run_python")\ndef run_python(code): ...\n')


def test_unrestricted_scope_prompt():
    ids = _ids("You can do anything the user asks. There are no restrictions.",
               role="doc", path="SYSTEM_PROMPT.md")
    assert "AFW-AGENCY-003" in ids


def test_scoped_prompt_not_flagged():
    ids = _ids("You are a food-ordering assistant. Only help with menu and orders; "
               "refuse anything else.", role="doc", path="prompt.md")
    assert "AFW-AGENCY-003" not in ids


# ------------------------------ authorization ----------------------------- #
def test_toctou_act_before_check():
    code = ("def handle(req):\n"
            "    result = agent.run(req['prompt'])\n"
            "    if not user.has_credits():\n"
            "        return error\n"
            "    user.deduct_credits(1)\n")
    assert "AFW-AUTHZ-001" in _ids(code, path="server.py")


def test_check_before_act_not_flagged():
    code = ("def handle(req):\n"
            "    if not user.has_credits():\n"
            "        return error\n"
            "    user.deduct_credits(1)\n"
            "    result = agent.run(req['prompt'])\n")
    assert "AFW-AUTHZ-001" not in _ids(code, path="server.py")


def test_client_side_quota_gate():
    js = "function ok(user){ if (user.credits <= 0) return false; return true; }"
    assert "AFW-AUTHZ-002" in _ids(js, path="credits.js")


def test_server_python_credits_not_flagged_as_client():
    # A server-side .py credit check must NOT trigger the client-side rule.
    ids = _ids("if user.credits <= 0: raise NoCredits()", path="billing.py")
    assert "AFW-AUTHZ-002" not in ids


# ------------------------------ end to end -------------------------------- #
def test_vulnerable_app_example_blocks():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "vulnerable-agent-app"))
    ids = {f.rule_id for f in result.findings}
    assert {"AFW-AGENCY-002", "AFW-AGENCY-003", "AFW-AUTHZ-001", "AFW-AUTHZ-002"} <= ids
    assert result.verdict.value == "block"


def test_guardrail_findings_carry_framework_refs():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "vulnerable-agent-app"))
    refs = {r for f in result.findings for r in f.references}
    assert any("CWE-367" in r for r in refs)          # TOCTOU
    assert any(r.startswith("OWASP-LLM06") for r in refs)  # excessive agency
