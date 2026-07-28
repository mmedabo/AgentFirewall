"""The scanner: run every rule over an artifact and reach a verdict."""
from __future__ import annotations

import json
from typing import Optional

from . import baseline as _baseline
from . import loaders
from .models import Artifact, Finding, ScanResult
from .policy import Policy
from .rules import Rule, all_rules


class Scanner:
    """Runs a set of rules against artifacts under a given policy."""

    def __init__(self, rules: Optional[list[Rule]] = None, policy: Optional[Policy] = None):
        self.rules = rules if rules is not None else all_rules()
        self.policy = policy or Policy.default()

    def scan_artifact(self, artifact: Artifact,
                      baseline: Optional[dict] = None) -> ScanResult:
        findings: list[Finding] = []
        for rule in self.rules:
            try:
                findings.extend(rule.check(artifact))
            except Exception as exc:  # a broken rule must not abort the scan
                findings.append(_rule_error(rule, exc))

        if baseline is not None:
            try:
                findings.extend(_baseline.diff(baseline, artifact))
            except Exception as exc:  # pragma: no cover - defensive
                findings.append(_rule_error(type("baseline", (), {"id": "AFW-DRIFT"})(), exc))

        findings = self.policy.filter(findings)
        findings = _dedupe(findings)
        findings.sort(key=lambda f: (-int(f.severity), f.rule_id, f.path, f.line))
        verdict = self.policy.decide(findings)
        return ScanResult(artifact=artifact, findings=findings, verdict=verdict)

    def scan_path(self, path: str, baseline_path: Optional[str] = None) -> ScanResult:
        try:
            artifact = loaders.load(path)
        except FileNotFoundError:
            return ScanResult(artifact=Artifact(name=path, root=path),
                              error=f"path not found: {path}")
        baseline = None
        if baseline_path:
            try:
                baseline = _baseline.load(baseline_path)
            except FileNotFoundError:
                return ScanResult(artifact=artifact,
                                  error=f"baseline not found: {baseline_path}")
            except (ValueError, json.JSONDecodeError) as exc:
                return ScanResult(artifact=artifact, error=f"invalid baseline: {exc}")
        return self.scan_artifact(artifact, baseline=baseline)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple] = set()
    out: list[Finding] = []
    for f in findings:
        key = (f.rule_id, f.path, f.line, f.evidence)
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _rule_error(rule: Rule, exc: Exception) -> Finding:
    from .models import Severity

    return Finding(
        rule_id=f"{getattr(rule, 'id', 'AFW')}-ERR",
        title="Rule execution error",
        severity=Severity.INFO,
        category="engine",
        message=f"Rule {type(rule).__name__} raised {type(exc).__name__}: {exc}",
        remediation="This is an internal issue; please report it.",
    )
