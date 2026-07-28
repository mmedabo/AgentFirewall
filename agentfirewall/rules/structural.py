"""Structural / heuristic rules that go beyond a single regex line match.

These inspect the *shape* of an artifact: prompt-injection phrasing in
instructions, invisible unicode, high-entropy encoded blobs, over-broad tool
permissions declared in manifests, and install-time hooks.
"""
from __future__ import annotations

import math
import re
import unicodedata
from typing import Iterable, Iterator

from ..models import Artifact, Finding, ScannedFile, Severity
from .base import Rule

# --------------------------------------------------------------------------- #
# Prompt injection / hidden instructions (targets the *model*, not the OS)
# --------------------------------------------------------------------------- #
_INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|prompts|rules)",
     "Attempts to override earlier instructions."),
    (r"disregard\s+(the\s+)?(system\s+prompt|previous|above|all\s+prior)",
     "Tells the model to disregard its system prompt."),
    (r"do\s+not\s+(tell|inform|mention|reveal|show)\s+(the\s+)?(user|human|operator)",
     "Instructs the agent to hide its actions from the user."),
    (r"without\s+(the\s+)?(user'?s?\s+)?(knowledge|consent|permission|awareness)",
     "Instructs the agent to act without user consent."),
    (r"(send|exfiltrate|upload|post|leak|forward)\s+[^\n]{0,60}"
     r"(api[_\s-]?key|secret|token|password|credential|\.env|ssh\s+key)",
     "Instructs the agent to send secrets to a third party."),
    (r"you\s+are\s+now\s+(a\s+)?(dan|developer\s+mode|unrestricted|jailbroken)",
     "Classic jailbreak persona-switch."),
    (r"(print|reveal|repeat|output)\s+(your|the)\s+(system\s+prompt|instructions|initial\s+prompt)",
     "Tries to extract the host system prompt."),
    (r"override\s+(your|the)\s+(safety|security|guardrails?|restrictions?)",
     "Tries to disable safety guardrails."),
]


class PromptInjectionRule(Rule):
    id = "AFW-INJ"
    category = "prompt-injection"

    def __init__(self) -> None:
        self._compiled = [(re.compile(p, re.IGNORECASE), m) for p, m in _INJECTION_PATTERNS]

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        for sf in artifact.files:
            if sf.is_binary:
                continue
            for lineno, line in enumerate(sf.lines, start=1):
                for pat, msg in self._compiled:
                    m = pat.search(line)
                    if not m:
                        continue
                    yield Finding(
                        rule_id="AFW-INJ-001",
                        title="Prompt-injection / hidden instruction",
                        severity=Severity.HIGH,
                        category=self.category,
                        message=msg,
                        path=sf.path,
                        line=lineno,
                        evidence=line.strip()[:200],
                        remediation="Remove instructions that manipulate the agent or hide actions from the user.",
                    )


# --------------------------------------------------------------------------- #
# Invisible / hidden unicode used to smuggle instructions past human review
# --------------------------------------------------------------------------- #
# Defined by codepoint so the source stays readable and can't itself be flagged.
_ZERO_WIDTH = {
    chr(cp) for cp in (
        0x200B,  # zero-width space
        0x200C,  # zero-width non-joiner
        0x200D,  # zero-width joiner
        0x2060,  # word joiner
        0xFEFF,  # zero-width no-break space / BOM
        0x180E,  # mongolian vowel separator
    )
}
_BIDI_CONTROLS = {
    chr(cp) for cp in (
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E,  # LRE RLE PDF LRO RLO
        0x2066, 0x2067, 0x2068, 0x2069,          # LRI RLI FSI PDI
    )
}
# Unicode Tag block (U+E0000..U+E007F) can encode invisible ASCII instructions.
_TAG_RANGE = range(0xE0000, 0xE0080)


class HiddenUnicodeRule(Rule):
    id = "AFW-UNI"
    category = "hidden-content"

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        for sf in artifact.files:
            if sf.is_binary:
                continue
            for lineno, line in enumerate(sf.lines, start=1):
                zw = sum(1 for ch in line if ch in _ZERO_WIDTH)
                bidi = [ch for ch in line if ch in _BIDI_CONTROLS]
                tags = sum(1 for ch in line if ord(ch) in _TAG_RANGE)
                if tags:
                    yield self._f(
                        "AFW-UNI-003", "Invisible unicode-tag instructions", Severity.CRITICAL,
                        f"Line contains {tags} Unicode Tag characters (U+E00xx) that can hide "
                        "machine-readable instructions from human reviewers.",
                        sf, lineno,
                        "Strip Unicode Tag characters; they have no legitimate use in agent docs.",
                    )
                if bidi:
                    names = ", ".join(sorted({_uname(ch) for ch in bidi}))
                    yield self._f(
                        "AFW-UNI-002", "Bidirectional-override characters", Severity.HIGH,
                        f"Line uses bidi control characters ({names}) that can reorder how text "
                        "is displayed versus how it is interpreted.",
                        sf, lineno,
                        "Remove bidirectional override characters.",
                    )
                if zw >= 2:
                    yield self._f(
                        "AFW-UNI-001", "Zero-width characters", Severity.MEDIUM,
                        f"Line contains {zw} zero-width characters, sometimes used to hide text.",
                        sf, lineno,
                        "Remove zero-width characters from documentation and prompts.",
                    )

    @staticmethod
    def _f(rid, title, sev, msg, sf: ScannedFile, line, rem) -> Finding:
        return Finding(rid, title, sev, "hidden-content", msg, sf.path, line,
                       evidence="<invisible characters>", remediation=rem)


def _uname(ch: str) -> str:
    try:
        return unicodedata.name(ch)
    except ValueError:  # pragma: no cover
        return f"U+{ord(ch):04X}"


# --------------------------------------------------------------------------- #
# High-entropy encoded blobs (packed payloads / embedded secrets)
# --------------------------------------------------------------------------- #
class EncodedBlobRule(Rule):
    id = "AFW-BLOB"
    category = "obfuscation"

    #: Minimum length of a base64-ish run before we care.
    MIN_LEN = 200
    #: Shannon entropy threshold (bits/char) above which a run looks packed.
    ENTROPY = 4.0

    _B64 = re.compile(r"[A-Za-z0-9+/=]{%d,}" % MIN_LEN)

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        for sf in artifact.files:
            if sf.is_binary:
                continue
            for lineno, line in enumerate(sf.lines, start=1):
                for m in self._B64.finditer(line):
                    blob = m.group(0)
                    if _entropy(blob) < self.ENTROPY:
                        continue
                    yield Finding(
                        rule_id="AFW-BLOB-001",
                        title="High-entropy encoded blob",
                        severity=Severity.MEDIUM,
                        category=self.category,
                        message=(f"A {len(blob)}-char high-entropy string (entropy "
                                 f"{_entropy(blob):.2f}) may be a packed payload or embedded secret."),
                        path=sf.path,
                        line=lineno,
                        evidence=blob[:48] + "…",
                        remediation="Decode and review large encoded blobs; agents rarely need them.",
                    )
                    break  # one finding per line is enough


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


# --------------------------------------------------------------------------- #
# Over-broad tool permissions declared in agent/skill manifests
# --------------------------------------------------------------------------- #
#: Tools that let an agent reach the shell or network arbitrarily. Routine
#: file tools (Read/Edit/Write) are deliberately excluded -- they are expected
#: for the vast majority of skills and flagging them would only add noise.
_DANGEROUS_TOOLS = {
    "bash", "shell", "execute", "exec", "run", "terminal", "computer",
    "webfetch", "websearch", "browser", "fetch",
}


class PermissionOverreachRule(Rule):
    id = "AFW-PERM"
    category = "permissions"
    file_roles = ("manifest",)

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        meta = artifact.metadata or {}
        declared = meta.get("declared_tools")
        if declared is None:
            return
        manifest_path = meta.get("manifest_path", artifact.name)

        # Wildcard / allow-all grants.
        for tool in declared:
            t = str(tool).strip()
            low = t.lower()
            if t in {"*", "all"} or low in {"*", "all"} or ".*" in t:
                yield Finding(
                    "AFW-PERM-001", "Wildcard tool permission", Severity.HIGH,
                    self.category,
                    f"Manifest grants itself all tools via '{t}', far more access than a "
                    "focused agent needs.",
                    manifest_path, 0, evidence=f"tools: {t}",
                    remediation="Declare only the specific tools the agent actually uses.",
                )
            elif low in _DANGEROUS_TOOLS or low.split("(")[0] in _DANGEROUS_TOOLS:
                yield Finding(
                    "AFW-PERM-002", "Powerful tool requested", Severity.LOW,
                    self.category,
                    f"Manifest requests the high-impact tool '{t}'. Legitimate, but review "
                    "that the artifact's behaviour justifies it.",
                    manifest_path, 0, evidence=f"tools: {t}",
                    remediation="Confirm this tool is required and its usage is safe.",
                )

        # Unrestricted Bash permission strings (Claude-style "Bash(*)" / "Bash").
        for perm in meta.get("declared_permissions", []) or []:
            p = str(perm)
            if re.fullmatch(r"(?i)bash(\(\s*\*?\s*\))?", p.strip()):
                yield Finding(
                    "AFW-PERM-003", "Unrestricted shell permission", Severity.MEDIUM,
                    self.category,
                    f"Permission '{p}' allows running any shell command without constraint.",
                    manifest_path, 0, evidence=f"permission: {p}",
                    remediation="Constrain Bash permissions to specific commands, e.g. Bash(git*).",
                )


# --------------------------------------------------------------------------- #
# Install-time hooks that run automatically on installation
# --------------------------------------------------------------------------- #
class InstallHookRule(Rule):
    id = "AFW-HOOK"
    category = "install-hook"

    _HOOK_KEYS = re.compile(
        r"\"(preinstall|postinstall|preuninstall|install)\"\s*:", re.IGNORECASE)
    _HOOK_FILES = ("hooks/", "postinstall", "preinstall", "setup.py", "install.sh")

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        for sf in artifact.files:
            if sf.is_binary:
                continue
            low = sf.path.lower()
            is_hook_file = any(h in low for h in self._HOOK_FILES)
            if sf.path.endswith("package.json"):
                for lineno, line in enumerate(sf.lines, start=1):
                    if self._HOOK_KEYS.search(line):
                        yield Finding(
                            "AFW-HOOK-001", "Automatic install script", Severity.MEDIUM,
                            self.category,
                            "Declares an npm install hook that runs automatically on install, "
                            "before you can review what it does.",
                            sf.path, lineno, evidence=line.strip()[:160],
                            remediation="Audit install hooks; they execute during `npm install`.",
                        )
            elif is_hook_file and sf.role in ("script", "config", "manifest"):
                yield Finding(
                    "AFW-HOOK-002", "Install/lifecycle hook file", Severity.LOW,
                    self.category,
                    "Contains a lifecycle/install hook file that may run automatically.",
                    sf.path, 0, evidence=sf.path,
                    remediation="Review hook scripts before installing.",
                )


STRUCTURAL_RULES: list[Rule] = [
    PromptInjectionRule(),
    HiddenUnicodeRule(),
    EncodedBlobRule(),
    PermissionOverreachRule(),
    InstallHookRule(),
]
