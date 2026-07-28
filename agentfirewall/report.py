"""Render :class:`ScanResult` objects for humans and machines."""
from __future__ import annotations

import json
import sys
from typing import Iterable

from .models import ScanResult, Severity, Verdict

# ANSI colours; disabled automatically when stdout is not a TTY.
_COLORS = {
    Severity.CRITICAL: "\033[97;41m",  # white on red
    Severity.HIGH: "\033[91m",
    Severity.MEDIUM: "\033[93m",
    Severity.LOW: "\033[94m",
    Severity.INFO: "\033[90m",
}
_VERDICT_COLORS = {
    Verdict.ALLOW: "\033[92m",
    Verdict.WARN: "\033[93m",
    Verdict.BLOCK: "\033[97;41m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"

_ICON = {
    Verdict.ALLOW: "✓",
    Verdict.WARN: "!",
    Verdict.BLOCK: "✗",
}


def _use_color(force: bool | None) -> bool:
    if force is not None:
        return force
    return sys.stdout.isatty()


def render_text(result: ScanResult, color: bool | None = None, verbose: bool = False) -> str:
    c = _use_color(color)

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if c else text

    a = result.artifact
    lines: list[str] = []
    lines.append(paint("AgentFirewall scan", _BOLD if c else ""))
    lines.append(f"  artifact : {a.name}  ({a.kind})")
    lines.append(f"  files    : {len(a.files)} scanned")
    if a.metadata.get("declared_tools"):
        lines.append(f"  tools    : {', '.join(a.metadata['declared_tools'])}")
    if a.metadata.get("mcp_servers"):
        lines.append(f"  mcp      : {', '.join(a.metadata['mcp_servers'])}")

    if result.error:
        lines.append("")
        lines.append(paint(f"  ERROR: {result.error}", _COLORS[Severity.HIGH]))
        return "\n".join(lines)

    counts = result.counts()
    summary = "  ".join(
        f"{s.label}:{counts[s.label]}" for s in reversed(Severity) if counts[s.label]
    ) or "no findings"
    lines.append(f"  findings : {summary}")
    lines.append("")

    if result.findings:
        for f in result.findings:
            tag = paint(f" {f.severity.label:^8} ", _COLORS[f.severity])
            lines.append(f"{tag} {paint(f.title, _BOLD if c else '')}  [{f.rule_id}]")
            lines.append(f"          {f.message}")
            lines.append(f"          → {f.location()}")
            if f.evidence:
                lines.append(f"          {paint(f.evidence, _COLORS[Severity.INFO])}")
            if f.references:
                lines.append(paint(f"          ⓘ {', '.join(f.references)}",
                                   _COLORS[Severity.INFO]))
            if verbose and f.remediation:
                lines.append(f"          fix: {f.remediation}")
            lines.append("")

    v = result.verdict
    banner = f"{_ICON[v]} VERDICT: {v.value.upper()}"
    lines.append(paint(f"  {banner}", _VERDICT_COLORS[v] + (_BOLD if c else "")))
    if v is Verdict.BLOCK:
        lines.append("  Installation should be blocked: high-risk behaviour detected.")
    elif v is Verdict.WARN:
        lines.append("  Proceed with caution: review the findings above before installing.")
    else:
        lines.append("  No blocking issues found.")
    return "\n".join(lines)


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def render_json_many(results: Iterable[ScanResult]) -> str:
    return json.dumps([r.to_dict() for r in results], indent=2)


# --------------------------------------------------------------------------- #
# SARIF 2.1.0 -- lets findings show up in GitHub code scanning / CI dashboards.
# --------------------------------------------------------------------------- #
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def render_sarif(results: list[ScanResult], version: str = "0.1.0") -> str:
    rule_index: dict[str, int] = {}
    rules_meta: list[dict] = []
    sarif_results: list[dict] = []

    for result in results:
        for f in result.findings:
            if f.rule_id not in rule_index:
                rule_index[f.rule_id] = len(rules_meta)
                rules_meta.append({
                    "id": f.rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.remediation or f.message},
                    "properties": {
                        "category": f.category,
                        "severity": f.severity.label,
                        "references": list(f.references),
                        "tags": list(f.references),
                    },
                })
            sarif_results.append({
                "ruleId": f.rule_id,
                "ruleIndex": rule_index[f.rule_id],
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f.message},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.path or result.artifact.name},
                        "region": {"startLine": max(1, f.line)},
                    }
                }],
            })

    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "AgentFirewall",
                "informationUri": "https://github.com/mmedabo/agentfirewall",
                "version": version,
                "rules": rules_meta,
            }},
            "results": sarif_results,
        }],
    }, indent=2)
