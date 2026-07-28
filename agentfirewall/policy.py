"""Policy: turns a set of findings into a firewall verdict.

The policy is what makes AgentFirewall a *firewall* rather than just a linter --
it decides whether an artifact is allowed through, waved through with a warning,
or blocked outright. Everything is configurable so a team can tighten or relax
the gate to fit their risk appetite.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any

from .models import Finding, Severity, Verdict


@dataclass
class Policy:
    """Configuration for how findings map to a verdict."""

    #: Any finding at or above this severity blocks the artifact.
    block_severity: Severity = Severity.HIGH
    #: Any finding at or above this severity (but below block) triggers a warning.
    warn_severity: Severity = Severity.LOW
    #: Rule ids (or category names) whose findings are suppressed entirely.
    ignore: set[str] = field(default_factory=set)
    #: If set, findings from these categories are downgraded to warnings.
    warn_only_categories: set[str] = field(default_factory=set)

    # ---- verdict logic --------------------------------------------------- #
    def filter(self, findings: list[Finding]) -> list[Finding]:
        """Drop suppressed findings."""
        return [f for f in findings if not self._suppressed(f)]

    def _suppressed(self, f: Finding) -> bool:
        return f.rule_id in self.ignore or f.category in self.ignore

    def _effective_severity(self, f: Finding) -> Severity:
        if f.category in self.warn_only_categories and f.severity >= self.block_severity:
            return Severity(self.block_severity - 1)
        return f.severity

    def decide(self, findings: list[Finding]) -> Verdict:
        """Compute the verdict for a (already-filtered) list of findings."""
        if not findings:
            return Verdict.ALLOW
        top = max(self._effective_severity(f) for f in findings)
        if top >= self.block_severity:
            return Verdict.BLOCK
        if top >= self.warn_severity:
            return Verdict.WARN
        return Verdict.ALLOW

    # ---- construction ---------------------------------------------------- #
    @classmethod
    def default(cls) -> "Policy":
        return cls()

    @classmethod
    def strict(cls) -> "Policy":
        """Block on anything MEDIUM or above -- for high-security environments."""
        return cls(block_severity=Severity.MEDIUM, warn_severity=Severity.LOW)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Policy":
        kwargs: dict[str, Any] = {}
        if "block_severity" in data:
            kwargs["block_severity"] = Severity.from_name(str(data["block_severity"]))
        if "warn_severity" in data:
            kwargs["warn_severity"] = Severity.from_name(str(data["warn_severity"]))
        if "ignore" in data:
            kwargs["ignore"] = set(data["ignore"] or [])
        if "warn_only_categories" in data:
            kwargs["warn_only_categories"] = set(data["warn_only_categories"] or [])
        return cls(**kwargs)

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
        data = _parse_config(text, path)
        return cls.from_dict(data)


def _parse_config(text: str, path: str) -> dict[str, Any]:
    """Parse a policy file as JSON, or a tiny YAML subset if PyYAML is absent."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".json":
        return json.loads(text)
    try:  # optional dependency; nice-to-have, not required
        import yaml  # type: ignore

        return yaml.safe_load(text) or {}
    except ImportError:
        return _mini_yaml(text)


def _mini_yaml(text: str) -> dict[str, Any]:
    """Parse the flat ``key: value`` / block-list policy schema without PyYAML."""
    out: dict[str, Any] = {}
    current: str | None = None
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if raw.strip().startswith("- ") and current is not None:
            out.setdefault(current, [])
            if isinstance(out[current], list):
                out[current].append(raw.strip()[2:].strip().strip("\"'"))
            continue
        if ":" in raw:
            key, _, value = raw.partition(":")
            key = key.strip()
            value = value.strip()
            current = key
            if value == "":
                out[key] = []
            elif value.startswith("[") and value.endswith("]"):
                out[key] = [v.strip().strip("\"'") for v in value[1:-1].split(",") if v.strip()]
            else:
                out[key] = value.strip("\"'")
    return out
