"""Baselining and drift detection -- the stateful, rug-pull defense.

A *baseline* (``afw.lock``) is a normalized fingerprint of an artifact at the
moment you approved it: a hash of every file plus a snapshot of its declared
*surface* (tools, permissions, MCP servers, and tool descriptions). On any later
scan you diff the current artifact against the baseline and flag drift.

This is the piece a purely static scan cannot provide. The dangerous MCP attacks
-- **rug pulls** and **insider updates** like the Postmark BCC incident -- ship a
clean version first and mutate later. Comparing against a pinned baseline catches
the mutation even when the new code contains no known-bad signature: a tool whose
*description* or *permissions* silently changed is, by itself, the alarm.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any

from . import frameworks as F
from .models import Artifact, Finding, Severity

SCHEMA_VERSION = 1
DEFAULT_LOCK_NAME = "afw.lock"


# --------------------------------------------------------------------------- #
# Building a baseline
# --------------------------------------------------------------------------- #
def compute(artifact: Artifact) -> dict[str, Any]:
    """Return a normalized, JSON-serializable fingerprint of ``artifact``."""
    files = {
        sf.path: sf.sha256
        for sf in sorted(artifact.files, key=lambda f: f.path)
        if sf.sha256
    }
    meta = artifact.metadata or {}
    tool_descs = {
        d.get("name", "?"): _norm(d.get("text", ""))
        for d in meta.get("tool_descriptions", []) or []
    }
    return {
        "schema": SCHEMA_VERSION,
        "name": artifact.name,
        "kind": artifact.kind,
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
        "surface": {
            "declared_tools": sorted(meta.get("declared_tools", []) or []),
            "declared_permissions": sorted(meta.get("declared_permissions", []) or []),
            "mcp_servers": sorted(meta.get("mcp_servers", []) or []),
            "tool_descriptions": tool_descs,
        },
    }


def write(path: str, artifact: Artifact) -> str:
    """Write a baseline for ``artifact`` to ``path`` (or a dir). Returns the path."""
    if os.path.isdir(path):
        path = os.path.join(path, DEFAULT_LOCK_NAME)
    data = compute(artifact)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def load(path: str) -> dict[str, Any]:
    if os.path.isdir(path):
        path = os.path.join(path, DEFAULT_LOCK_NAME)
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


# --------------------------------------------------------------------------- #
# Diffing against a baseline
# --------------------------------------------------------------------------- #
def diff(baseline: dict[str, Any], artifact: Artifact) -> list[Finding]:
    """Findings describing how ``artifact`` drifted from ``baseline``."""
    findings: list[Finding] = []
    loc = artifact.metadata.get("manifest_path", artifact.name)

    findings.extend(_diff_files(baseline.get("files", {}), artifact))
    findings.extend(_diff_surface(baseline.get("surface", {}), artifact, loc))
    return findings


def _diff_files(old: dict[str, str], artifact: Artifact) -> list[Finding]:
    out: list[Finding] = []
    now = {sf.path: sf.sha256 for sf in artifact.files if sf.sha256}
    roles = {sf.path: sf.role for sf in artifact.files}

    for path, old_hash in old.items():
        new_hash = now.get(path)
        if new_hash is None:
            out.append(_f("AFW-DRIFT-004", "Baselined file removed", Severity.LOW,
                          f"File '{path}' present at pin time is gone.", path,
                          "Confirm the removal is expected."))
        elif new_hash != old_hash:
            role = roles.get(path, "file")
            sev = Severity.HIGH if role in ("script", "manifest", "config") else Severity.MEDIUM
            out.append(_f("AFW-DRIFT-001", "Baselined file changed", sev,
                          f"'{path}' changed since it was pinned ({role}). A silent update to "
                          "an approved file is the core of a rug-pull attack.",
                          path, "Re-review the changes, then re-pin if they are legitimate.",
                          rug=True))
    for path, _new in now.items():
        if path not in old:
            role = roles.get(path, "file")
            sev = Severity.MEDIUM if role in ("script", "manifest", "config") else Severity.LOW
            out.append(_f("AFW-DRIFT-002", "New file since baseline", sev,
                          f"'{path}' was added after the artifact was pinned.",
                          path, "Review newly added files before trusting the update.",
                          rug=True))
    return out


def _diff_surface(old: dict[str, Any], artifact: Artifact, loc: str) -> list[Finding]:
    out: list[Finding] = []
    meta = artifact.metadata or {}

    new_tools = set(meta.get("declared_tools", []) or [])
    old_tools = set(old.get("declared_tools", []) or [])
    for added in sorted(new_tools - old_tools):
        out.append(_f("AFW-DRIFT-010", "Tool grant added since baseline", Severity.CRITICAL,
                      f"The artifact now requests tool '{added}', which it did not have when "
                      "pinned. Silent privilege escalation is a hallmark of a rug pull.",
                      loc, "Treat new tool grants as a fresh trust decision.", rug=True,
                      evidence=f"+{added}"))

    new_perms = set(meta.get("declared_permissions", []) or [])
    old_perms = set(old.get("declared_permissions", []) or [])
    for added in sorted(new_perms - old_perms):
        out.append(_f("AFW-DRIFT-011", "Permission added since baseline", Severity.HIGH,
                      f"New permission '{added}' appeared since the artifact was pinned.",
                      loc, "Review the added permission.", rug=True, evidence=f"+{added}"))

    new_srv = set(meta.get("mcp_servers", []) or [])
    old_srv = set(old.get("mcp_servers", []) or [])
    for added in sorted(new_srv - old_srv):
        out.append(_f("AFW-DRIFT-012", "MCP server added since baseline", Severity.HIGH,
                      f"A new MCP server '{added}' was added after pinning.",
                      loc, "Confirm the new server is trusted.", rug=True, evidence=f"+{added}"))

    old_desc = old.get("tool_descriptions", {}) or {}
    new_desc = {d.get("name", "?"): _norm(d.get("text", ""))
                for d in meta.get("tool_descriptions", []) or []}
    for name, text in new_desc.items():
        if name in old_desc and old_desc[name] != text:
            out.append(_f("AFW-DRIFT-013", "Tool description changed since baseline",
                          Severity.HIGH,
                          f"The description of tool '{name}' changed after pinning. Rug-pull "
                          "tool-poisoning works by mutating a description the model trusts.",
                          loc, "Re-review the tool description for injected instructions.",
                          rug=True, evidence=name))
    return out


def _norm(text: str) -> str:
    return " ".join(str(text).split())


def _f(rid: str, title: str, sev: Severity, msg: str, path: str, rem: str,
       rug: bool = False, evidence: str = "") -> Finding:
    refs = (F.MCP_RUG_PULL, F.AGENTIC_PRIVILEGE_COMPROMISE) if rug else (F.SLSA_PROVENANCE,)
    return Finding(rid, title, sev, "rug-pull" if rug else "integrity", msg,
                   path=path, evidence=evidence, remediation=rem, references=refs)
