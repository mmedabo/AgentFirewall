"""End-to-end scanner tests over the bundled example artifacts."""
import os

import pytest

from agentfirewall import Policy, Scanner, Severity, Verdict

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def _result(path):
    return Scanner().scan_path(os.path.join(EXAMPLES, path))


def test_safe_skill_is_allowed():
    result = _result("safe-skill")
    assert result.verdict is Verdict.ALLOW
    assert result.max_severity is None or result.max_severity < Severity.HIGH


def test_malicious_skill_is_blocked():
    result = _result("malicious-skill")
    assert result.verdict is Verdict.BLOCK
    assert result.max_severity is Severity.CRITICAL


def test_malicious_skill_flags_expected_categories():
    result = _result("malicious-skill")
    categories = {f.category for f in result.findings}
    for expected in {
        "secret-access", "exfiltration", "obfuscation",
        "destructive", "prompt-injection", "permissions",
    }:
        assert expected in categories, f"missing category {expected}: {categories}"


def test_reverse_shell_and_curl_bash_are_critical():
    result = _result("malicious-skill")
    ids = {f.rule_id for f in result.findings}
    assert "AFW-OBF-001" in ids  # curl | bash
    assert "AFW-SEC-001" in ids  # ssh key
    assert "AFW-INJ-001" in ids  # prompt injection


def test_wildcard_tools_flagged():
    result = _result("malicious-skill")
    ids = {f.rule_id for f in result.findings}
    assert "AFW-PERM-001" in ids


def test_policy_ignore_suppresses_rule():
    policy = Policy(ignore={"AFW-INJ-001"})
    scanner = Scanner(policy=policy)
    result = scanner.scan_path(os.path.join(EXAMPLES, "malicious-skill"))
    assert all(f.rule_id != "AFW-INJ-001" for f in result.findings)


def test_strict_policy_blocks_more():
    strict = Policy.strict()
    assert strict.block_severity is Severity.MEDIUM


def test_missing_path_reports_error():
    result = Scanner().scan_path("/nonexistent/path/xyz")
    assert result.error is not None
    assert result.verdict is Verdict.ALLOW  # no findings, but errored


def test_findings_sorted_by_severity_desc():
    result = _result("malicious-skill")
    sevs = [int(f.severity) for f in result.findings]
    assert sevs == sorted(sevs, reverse=True)
