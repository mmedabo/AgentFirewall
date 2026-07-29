"""The scanner: run every rule over an artifact and reach a verdict."""
from __future__ import annotations

import json
import os
from typing import Optional

from . import baseline as _baseline
from . import loaders
from . import provenance as _provenance
from .intel import ThreatIntel
from .models import Artifact, Finding, ScanResult, TrustTier
from .policy import Policy
from .rules import Rule, all_rules


class Scanner:
    """Runs a set of rules against artifacts under a given policy."""

    def __init__(self, rules: Optional[list[Rule]] = None, policy: Optional[Policy] = None,
                 intel: Optional[ThreatIntel] = None, verify_signatures: bool = False,
                 expected_identity: Optional[str] = None):
        self.rules = rules if rules is not None else all_rules()
        self.policy = policy or Policy.default()
        self.intel = intel
        self.verify_signatures = verify_signatures
        self.expected_identity = expected_identity

    def scan_artifact(self, artifact: Artifact, baseline: Optional[dict] = None,
                      pinned: bool = False) -> ScanResult:
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

        # Provenance & trust tier (Phase 3).
        prov = _provenance.detect(
            artifact, pinned=pinned or baseline is not None,
            verify=self.verify_signatures, expected_identity=self.expected_identity)
        findings.extend(_provenance.findings_for(prov, artifact))

        # Threat-intel / IoC matching.
        if self.intel is not None and not self.intel.is_empty():
            findings.extend(self.intel.check(artifact))
            findings.extend(self.intel.check_signer(prov.signer or "", artifact))

        findings = self.policy.filter(findings)
        findings = _dedupe(findings)
        findings.sort(key=lambda f: (-int(f.severity), f.rule_id, f.path, f.line))
        verdict = self.policy.decide(findings, trust_tier=prov.tier)
        return ScanResult(artifact=artifact, findings=findings, verdict=verdict,
                          trust_tier=prov.tier, provenance=prov.to_dict())

    def scan_path(self, path: str, baseline_path: Optional[str] = None) -> ScanResult:
        try:
            artifact = loaders.load(path)
        except FileNotFoundError:
            return ScanResult(artifact=Artifact(name=path, root=path),
                              error=f"path not found: {path}")
        baseline = None
        pinned = False
        if baseline_path:
            try:
                baseline = _baseline.load(baseline_path)
                pinned = True
            except FileNotFoundError:
                return ScanResult(artifact=artifact,
                                  error=f"baseline not found: {baseline_path}")
            except (ValueError, json.JSONDecodeError) as exc:
                return ScanResult(artifact=artifact, error=f"invalid baseline: {exc}")
        elif os.path.isdir(path) and os.path.exists(
                os.path.join(path, _baseline.DEFAULT_LOCK_NAME)):
            # An adjacent afw.lock counts as a local trust anchor even without --baseline.
            pinned = True
        return self.scan_artifact(artifact, baseline=baseline, pinned=pinned)


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
