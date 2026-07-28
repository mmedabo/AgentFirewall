"""Rule engine primitives.

A *rule* inspects an :class:`~agentfirewall.models.Artifact` and yields
:class:`~agentfirewall.models.Finding` objects. Rules are deliberately small and
composable so the community can add new detections without touching the engine.

Two building blocks are provided:

* :class:`Rule`      -- the base class every detection extends.
* :class:`PatternRule` -- a batteries-included rule that scans the text of every
  file for a set of regular expressions. The vast majority of signature-style
  detections are just data (a regex + a severity + a message), so ``PatternRule``
  turns them into a one-liner.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator, Pattern, Sequence, Union

from ..models import Artifact, Finding, ScannedFile, Severity


class Rule:
    """Base class for all detections.

    Subclasses set ``id``, ``category`` and implement :meth:`check`.
    """

    id: str = "AFW000"
    category: str = "generic"
    #: Roles of files this rule cares about. Empty == every text file.
    file_roles: tuple[str, ...] = ()

    def applies_to(self, sf: ScannedFile) -> bool:
        if sf.is_binary:
            return False
        if self.file_roles and sf.role not in self.file_roles:
            return False
        return True

    def check(self, artifact: Artifact) -> Iterable[Finding]:  # pragma: no cover
        raise NotImplementedError


@dataclass
class Signature:
    """A single regex signature used by :class:`PatternRule`."""

    id: str
    title: str
    severity: Severity
    pattern: Pattern[str]
    message: str
    remediation: str = ""
    #: Only flag when the regex matches; optional second regex that must ALSO be
    #: present somewhere in the same file for the finding to fire (context gate).
    requires_also: Pattern[str] | None = None


def compile_sig(
    id: str,
    title: str,
    severity: Severity,
    pattern: str,
    message: str,
    remediation: str = "",
    flags: int = re.IGNORECASE,
    requires_also: str | None = None,
) -> Signature:
    return Signature(
        id=id,
        title=title,
        severity=severity,
        pattern=re.compile(pattern, flags),
        message=message,
        remediation=remediation,
        requires_also=re.compile(requires_also, flags) if requires_also else None,
    )


class PatternRule(Rule):
    """Scans every applicable file line-by-line against a set of signatures."""

    def __init__(
        self,
        id: str,
        category: str,
        signatures: Sequence[Signature],
        file_roles: tuple[str, ...] = (),
    ) -> None:
        self.id = id
        self.category = category
        self.signatures = list(signatures)
        self.file_roles = file_roles

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        for sf in artifact.files:
            if not self.applies_to(sf):
                continue
            for sig in self.signatures:
                if sig.requires_also and not sig.requires_also.search(sf.text):
                    continue
                for lineno, line in enumerate(sf.lines, start=1):
                    m = sig.pattern.search(line)
                    if not m:
                        continue
                    yield Finding(
                        rule_id=sig.id,
                        title=sig.title,
                        severity=sig.severity,
                        category=self.category,
                        message=sig.message,
                        path=sf.path,
                        line=lineno,
                        evidence=_snippet(line, m),
                        remediation=sig.remediation,
                    )


def _snippet(line: str, match: "re.Match[str]", width: int = 160) -> str:
    """Return a trimmed, single-line snippet around ``match`` for display."""
    text = line.strip()
    if len(text) <= width:
        return text
    start = max(0, match.start() - width // 2)
    end = min(len(line), start + width)
    prefix = "…" if start > 0 else ""
    suffix = "…" if end < len(line) else ""
    return f"{prefix}{line[start:end].strip()}{suffix}"


PatternInput = Union[Signature, Sequence[Signature]]
