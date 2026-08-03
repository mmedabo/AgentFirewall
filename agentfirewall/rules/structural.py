"""Structural / heuristic rules that go beyond a single regex line match.

These inspect the *shape* of an artifact: prompt-injection phrasing in
instructions, invisible unicode, high-entropy encoded blobs, over-broad tool
permissions declared in manifests, and install-time hooks.
"""
from __future__ import annotations

import math
import os
import re
import unicodedata
from typing import Iterable, Iterator

from .. import frameworks as F
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
                        references=(F.LLM01_PROMPT_INJECTION, F.ATLAS_LLM_PROMPT_INJECTION),
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
                       evidence="<invisible characters>", remediation=rem,
                       references=(F.LLM01_PROMPT_INJECTION, F.MCP_TOOL_POISONING))


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
                        references=(F.ATLAS_DEFENSE_EVASION, F.LLM02_SENSITIVE_INFO),
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
        manifest_path = meta.get("manifest_path", artifact.name)

        # MCP servers that bake secrets into `env` or auto-approve their tools.
        # (Runs independently of declared tools, since MCP configs have none.)
        for issue in meta.get("mcp_risks", []) or []:
            refs = tuple(issue.get("references")
                         or (F.LLM06_EXCESSIVE_AGENCY, F.AGENTIC_PRIVILEGE_COMPROMISE))
            yield Finding(
                issue["rule_id"], issue["title"], Severity.from_name(issue["severity"]),
                self.category, issue["message"], manifest_path, 0,
                evidence=issue.get("evidence", ""),
                remediation=issue.get("remediation", ""),
                references=refs,
            )

        declared = meta.get("declared_tools")
        if declared is None:
            return

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
                    references=(F.LLM06_EXCESSIVE_AGENCY, F.AGENTIC_PRIVILEGE_COMPROMISE),
                )
            elif low in _DANGEROUS_TOOLS or low.split("(")[0] in _DANGEROUS_TOOLS:
                yield Finding(
                    "AFW-PERM-002", "Powerful tool requested", Severity.LOW,
                    self.category,
                    f"Manifest requests the high-impact tool '{t}'. Legitimate, but review "
                    "that the artifact's behaviour justifies it.",
                    manifest_path, 0, evidence=f"tools: {t}",
                    remediation="Confirm this tool is required and its usage is safe.",
                    references=(F.LLM06_EXCESSIVE_AGENCY,),
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
                    references=(F.LLM06_EXCESSIVE_AGENCY, F.AGENTIC_TOOL_MISUSE),
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
                            references=(F.LLM03_SUPPLY_CHAIN, F.ATLAS_EXECUTION),
                        )
            elif is_hook_file and sf.role in ("script", "config", "manifest"):
                yield Finding(
                    "AFW-HOOK-002", "Install/lifecycle hook file", Severity.LOW,
                    self.category,
                    "Contains a lifecycle/install hook file that may run automatically.",
                    sf.path, 0, evidence=sf.path,
                    remediation="Review hook scripts before installing.",
                    references=(F.LLM03_SUPPLY_CHAIN,),
                )


# --------------------------------------------------------------------------- #
# Tool poisoning: hidden directives embedded in tool/skill *descriptions*
# (Invariant Labs, Apr 2025). The description lands in the model's context, so an
# imperative hidden there can steer the agent even though the code looks clean.
# --------------------------------------------------------------------------- #
class ToolPoisoningRule(Rule):
    id = "AFW-TPZ"
    category = "tool-poisoning"
    file_roles = ("manifest",)

    _MARKERS = re.compile(
        r"<\s*(important|system|secret|admin|instructions?)\s*>|"
        r"\bbefore\s+(using|calling|invoking)\s+this\s+tool\b|"
        r"\b(you\s+must|always)\s+(first\s+)?(read|open|send|include|cat|fetch)\b|"
        r"\bdo\s+not\s+(tell|mention|inform|reveal)\b|"
        r"\b(read|include|attach|send)\b[^\n]{0,40}(~/\.|/etc/|\.env|\.ssh|api[_\s-]?key|"
        r"mnemonic|config)\b|"
        r"\bsidenote\b[^\n]{0,20}\bassistant\b",
        re.IGNORECASE,
    )

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        # Structured tool descriptions extracted by the loader (MCP servers).
        for desc in artifact.metadata.get("tool_descriptions", []) or []:
            text = desc.get("text", "")
            m = self._MARKERS.search(text)
            if m:
                yield Finding(
                    "AFW-TPZ-001", "Tool description contains hidden directive",
                    Severity.HIGH, self.category,
                    f"The description of tool '{desc.get('name', '?')}' embeds an instruction "
                    "to the model ('tool poisoning'); descriptions are injected into context.",
                    artifact.metadata.get("manifest_path", artifact.name), 0,
                    evidence=_clip(text, m),
                    remediation="Tool descriptions must describe, not instruct. Remove directives.",
                    references=(F.MCP_TOOL_POISONING, F.LLM01_PROMPT_INJECTION,
                                F.ATLAS_LLM_PLUGIN_COMPROMISE),
                )
        # Fallback: scan raw manifest text for the same markers.
        for sf in artifact.files:
            if sf.is_binary or sf.role != "manifest":
                continue
            for lineno, line in enumerate(sf.lines, start=1):
                m = self._MARKERS.search(line)
                if m:
                    yield Finding(
                        "AFW-TPZ-002", "Directive embedded in manifest/metadata",
                        Severity.HIGH, self.category,
                        "A manifest/metadata line embeds an instruction to the model rather "
                        "than describing behaviour (possible tool poisoning).",
                        sf.path, lineno, evidence=line.strip()[:200],
                        remediation="Keep manifests declarative; move instructions out of metadata.",
                        references=(F.MCP_TOOL_POISONING, F.LLM01_PROMPT_INJECTION),
                    )


# --------------------------------------------------------------------------- #
# Typosquatting / impersonation of well-known agents, skills and servers.
# --------------------------------------------------------------------------- #
#: A small seed list of popular ecosystem names. Communities can extend it.
_POPULAR_NAMES = {
    "github", "gitlab", "slack", "notion", "linear", "stripe", "postgres",
    "sqlite", "filesystem", "puppeteer", "playwright", "brave-search",
    "google-drive", "gmail", "sentry", "cloudflare", "anthropic", "openai",
    "kubernetes", "docker", "aws", "azure", "jira", "confluence",
}

#: Confusable characters that make one name look like another.
_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p",  # Cyrillic
    "с": "c", "х": "x", "ԁ": "d",
    "ᴜ": "u", "K": "k",
}


class TyposquatRule(Rule):
    id = "AFW-SQT"
    category = "typosquatting"

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        name = str(artifact.metadata.get("declared_name") or artifact.name).strip()
        base = name.rsplit("/", 1)[-1].lower()
        base = re.sub(r"[-_. ]+", "-", base)
        if not base:
            return

        # 1. Homoglyph / non-ASCII characters in the name (impersonation).
        confusables = [ch for ch in name if ch in _HOMOGLYPHS or ord(ch) > 0x7F]
        if confusables:
            normalized = "".join(_HOMOGLYPHS.get(ch, ch) for ch in base)
            yield Finding(
                "AFW-SQT-001", "Confusable characters in name", Severity.MEDIUM,
                self.category,
                f"Artifact name '{name}' uses look-alike/non-ASCII characters "
                f"(resembles '{normalized}'), a common impersonation trick.",
                artifact.metadata.get("manifest_path", artifact.name), 0,
                evidence=name,
                remediation="Use a plain ASCII name; verify you are installing the genuine artifact.",
                references=(F.SUPPLY_TYPOSQUATTING, F.AGENTIC_IDENTITY_SPOOFING),
            )

        # 2. Near-miss of a popular name (typosquat), but not an exact match.
        deglyph = "".join(_HOMOGLYPHS.get(ch, ch) for ch in base)
        for popular in _POPULAR_NAMES:
            if deglyph == popular:
                continue
            if _within_edit_distance(deglyph, popular, 1) and abs(len(deglyph) - len(popular)) <= 1:
                yield Finding(
                    "AFW-SQT-002", "Name resembles a popular package", Severity.MEDIUM,
                    self.category,
                    f"Name '{base}' is one edit away from the well-known '{popular}' — "
                    "possible typosquat or dependency-confusion bait.",
                    artifact.metadata.get("manifest_path", artifact.name), 0,
                    evidence=f"{base} ≈ {popular}",
                    remediation=f"Confirm this is not an impersonation of '{popular}'.",
                    references=(F.SUPPLY_TYPOSQUATTING, F.LLM03_SUPPLY_CHAIN),
                )
                break


def _within_edit_distance(a: str, b: str, max_d: int) -> bool:
    """True if Levenshtein(a, b) <= max_d. Cheap early-exit implementation."""
    if abs(len(a) - len(b)) > max_d:
        return False
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = cur[0]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
            best = min(best, cur[-1])
        if best > max_d:
            return False
        prev = cur
    return prev[-1] <= max_d


def _clip(text: str, match: "re.Match[str]", width: int = 160) -> str:
    text = " ".join(text.split())
    return text if len(text) <= width else text[:width] + "…"


# --------------------------------------------------------------------------- #
# Business-logic guardrails for a DEPLOYED agent app: is the expensive/mutating
# agent action properly gated by authorization *before* it runs? (The Bolt.new
# refresh exploit: the "out of credits" check fired after the agent had already
# started, and a refresh replayed the queued prompt.)
# --------------------------------------------------------------------------- #
_ACT = re.compile(
    r"(?i)\b(openai|anthropic)\b|\.chat\.completions\.create|\.messages\.create|"
    r"\bllm\.\w+|model\.generate|\bgenerate(_?text)?\s*\(|streamText\s*\(|"
    r"\bagent\.run\b|\brun_agent\b|\.invoke\s*\(|completions?\.create")
_CHECK = re.compile(
    r"(?i)\b(check_credits|has_credits|hascredits|deduct_credits|decrement_credits|"
    r"spend_credits|use_credits|check_quota|checkquota|authorize|can_afford|"
    r"require_credits|assert_credits|is_out_of_credits|isoutofcredits|rate_?limit|"
    r"remaining_credits|credits_left|creditsleft)\b|\bcredits\s*[<>]=?|credits\s*-=")
_CLIENT_EXT = (".js", ".ts", ".jsx", ".tsx", ".vue", ".svelte")
_CLIENT_GATE = re.compile(
    r"(?i)\b(credits|tokensleft|tokens_left|remainingcredits|isoutofcredits|"
    r"hascredits|quota)\b[^\n]{0,20}([<>]=?|===?|!==?)")


class BusinessLogicRule(Rule):
    """Check-after-act / client-side-only enforcement in a deployed agent app."""

    id = "AFW-AUTHZ"
    category = "authorization"

    def check(self, artifact: Artifact) -> Iterator[Finding]:
        for sf in artifact.files:
            if sf.is_binary:
                continue

            # 1. Model invoked before the quota/authorization check (TOCTOU).
            if sf.role == "script":
                act_line = check_line = None
                for lineno, line in enumerate(sf.lines, start=1):
                    if act_line is None and _ACT.search(line):
                        act_line = lineno
                    if check_line is None and _CHECK.search(line):
                        check_line = lineno
                if (act_line is not None and check_line is not None
                        and act_line < check_line and (check_line - act_line) <= 100):
                    yield Finding(
                        "AFW-AUTHZ-001", "Authorization/quota checked after the agent ran",
                        Severity.HIGH, self.category,
                        f"The model/agent is invoked (line {act_line}) before the quota/"
                        f"authorization check (line {check_line}). This check-after-act "
                        "ordering lets a request slip through on retry/refresh before the "
                        "check completes (TOCTOU) — the Bolt.new refresh-exploit pattern.",
                        sf.path, act_line, evidence=sf.lines[act_line - 1].strip()[:160],
                        remediation="Authorize and atomically reserve/deduct quota BEFORE "
                        "invoking the agent; make the operation idempotent by request id.",
                        references=(F.CWE_TOCTOU, F.API_BROKEN_AUTHZ, F.LLM10_UNBOUNDED),
                    )

            # 2. Quota/limit gating that lives in client-side code.
            if os.path.splitext(sf.path)[1].lower() in _CLIENT_EXT:
                for lineno, line in enumerate(sf.lines, start=1):
                    if _CLIENT_GATE.search(line):
                        yield Finding(
                            "AFW-AUTHZ-002", "Quota/credit gate in client-side code",
                            Severity.MEDIUM, self.category,
                            "Credit/quota logic appears in client-side code. Client checks are "
                            "trivially bypassed by replaying the request — enforce the limit "
                            "server-side before the agent runs.",
                            sf.path, lineno, evidence=line.strip()[:160],
                            remediation="Enforce quota on the server before invoking the agent; "
                            "treat any client-side check as UX only.",
                            references=(F.CWE_CLIENT_ENFORCE, F.API_RESOURCE, F.LLM10_UNBOUNDED),
                        )
                        break  # one per file is enough


STRUCTURAL_RULES: list[Rule] = [
    PromptInjectionRule(),
    HiddenUnicodeRule(),
    EncodedBlobRule(),
    PermissionOverreachRule(),
    InstallHookRule(),
    ToolPoisoningRule(),
    TyposquatRule(),
    BusinessLogicRule(),
]
