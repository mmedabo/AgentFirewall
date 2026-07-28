"""Core data models for AgentFirewall.

These dataclasses describe the vocabulary the whole tool speaks in: what a
*finding* is, how severe it is, and what verdict the firewall reaches about a
scanned agent artifact.
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from typing import Any, Optional


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value == more dangerous.

    The integer ordering lets us compare, sort and threshold findings easily
    (e.g. ``finding.severity >= Severity.HIGH``).
    """

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        try:
            return cls[name.strip().upper()]
        except KeyError as exc:  # pragma: no cover - defensive
            raise ValueError(f"Unknown severity: {name!r}") from exc

    @property
    def label(self) -> str:
        return self.name


class Verdict(enum.Enum):
    """The firewall's decision about an artifact."""

    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"

    @property
    def exit_code(self) -> int:
        return {Verdict.ALLOW: 0, Verdict.WARN: 0, Verdict.BLOCK: 2}[self]


class TrustTier(enum.IntEnum):
    """How much independent provenance backs an artifact.

    Higher == more trustworthy. Drives policy: an ``UNTRUSTED`` artifact (no
    signature, no attestation, not locally pinned) is held to a stricter bar.
    """

    UNTRUSTED = 0  # no provenance signals at all
    DECLARED = 1   # signature/attestation/SBOM files present but NOT verified
    PINNED = 2     # user holds a local baseline (afw.lock) for it
    VERIFIED = 3   # a signature was cryptographically verified

    @property
    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True)
class Finding:
    """A single suspicious thing discovered in an artifact."""

    rule_id: str
    title: str
    severity: Severity
    category: str
    message: str
    path: str = ""
    line: int = 0
    evidence: str = ""
    remediation: str = ""
    #: External framework references this detection maps to, e.g.
    #: ("OWASP-LLM01", "MITRE-ATLAS:AML.T0051", "MCP:tool-poisoning").
    references: tuple[str, ...] = ()

    def location(self) -> str:
        if self.path and self.line:
            return f"{self.path}:{self.line}"
        return self.path or "<artifact>"

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "category": self.category,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass
class ScannedFile:
    """A file pulled out of an artifact, ready to be inspected."""

    path: str  # display path, relative to the artifact root
    text: str
    is_binary: bool = False
    role: str = "file"  # e.g. "manifest", "script", "doc", "config"
    sha256: str = ""  # content hash, used for baseline/rug-pull diffing

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()


@dataclass
class Artifact:
    """The thing being scanned: a skill, agent, MCP server, plugin, etc."""

    name: str
    root: str
    kind: str = "unknown"  # skill | agent | mcp | plugin | archive | directory
    files: list[ScannedFile] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """The full outcome of scanning one artifact."""

    artifact: Artifact
    findings: list[Finding] = field(default_factory=list)
    verdict: Verdict = Verdict.ALLOW
    error: Optional[str] = None
    trust_tier: TrustTier = TrustTier.UNTRUSTED
    provenance: Optional[dict[str, Any]] = None

    @property
    def max_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        return max(f.severity for f in self.findings)

    def counts(self) -> dict[str, int]:
        out = {s.label: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.label] += 1
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "artifact": {
                "name": self.artifact.name,
                "root": self.artifact.root,
                "kind": self.artifact.kind,
                "files_scanned": len(self.artifact.files),
                "metadata": self.artifact.metadata,
            },
            "verdict": self.verdict.value,
            "trust_tier": self.trust_tier.label,
            "provenance": self.provenance,
            "max_severity": self.max_severity.label if self.max_severity else None,
            "counts": self.counts(),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }
