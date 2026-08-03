"""Threat intelligence / IoC feeds (Phase 3).

The signature engine answers "does this artifact *behave* badly?". Threat intel
answers a different question: "is this artifact *known* to be bad?" -- by name,
by file hash, by the domains it contacts, or by a revoked signer identity. This is
the firewall analog of an IP/domain blocklist fed from threat-intel.

Feeds are **offline by default**: a tiny illustrative seed ships with the package,
and users point ``--intel`` at their own lists (JSON or plain text). Nothing is
fetched from the network unless a user wires that up themselves.

Feed formats
------------
* **JSON**: ``{"names": [...], "domains": [...], "hashes": [...], "signers": [...]}``
* **Plain text**: one entry per line; the *category* is taken from the file name
  stem -- ``names.txt``, ``domains.txt``, ``hashes.txt``, ``signers.txt``.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Iterable

from . import frameworks as F
from .models import Artifact, Finding, Severity

_DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "intel")
_USER_DIR = os.path.expanduser("~/.config/agentfirewall/intel")

# Reuse the homoglyph map for name normalization (kept local to avoid a cycle).
_HOMOGLYPHS = {
    "0": "o", "1": "l", "3": "e", "5": "s", "$": "s", "@": "a",
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
}


def _norm_name(name: str) -> str:
    base = str(name).rsplit("/", 1)[-1].lower()
    base = "".join(_HOMOGLYPHS.get(ch, ch) for ch in base)
    return re.sub(r"[-_. ]+", "-", base).strip("-")


_IMPORT_PY = re.compile(r"^\s*(?:import|from)\s+([A-Za-z0-9_]+)")
_IMPORT_JS = re.compile(r"""(?:require\(|from\s+)['"]([^'"]+)['"]""")
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]+)\s*(?:[=<>~!\[;]|$)")
_PKG_DEP = re.compile(r'"([^"]+)"\s*:\s*"[^"]*"')


def _referenced_packages(text: str, path: str):
    """Yield (package_name, lineno) for imports / requirements / package.json deps."""
    low = path.lower()
    is_req = low.endswith(".txt") or "requirements" in low
    is_pkgjson = low.endswith("package.json")
    is_py = low.endswith(".py")
    refs = set()
    for i, line in enumerate(text.splitlines(), start=1):
        if is_py:
            m = _IMPORT_PY.match(line)
            if m:
                refs.add((m.group(1).lower(), i))
        for m in _IMPORT_JS.finditer(line):
            name = m.group(1)
            if name.startswith("."):
                continue
            base = ("/".join(name.split("/")[:2]) if name.startswith("@")
                    else name.split("/")[0])
            refs.add((base.lower(), i))
        if is_req:
            m = _REQ_LINE.match(line)
            if m and not line.lstrip().startswith("#"):
                refs.add((m.group(1).lower(), i))
        if is_pkgjson:
            for m in _PKG_DEP.finditer(line):
                refs.add((m.group(1).lower(), i))
    return refs


@dataclass
class ThreatIntel:
    """A merged set of indicators of compromise."""

    bad_names: set[str] = field(default_factory=set)      # normalized
    bad_domains: set[str] = field(default_factory=set)    # lowercased
    bad_hashes: set[str] = field(default_factory=set)     # lowercased sha256
    revoked_signers: set[str] = field(default_factory=set)
    suspect_packages: set[str] = field(default_factory=set)  # lowercased dependency names
    sources: list[str] = field(default_factory=list)

    # ---- construction ---------------------------------------------------- #
    @classmethod
    def empty(cls) -> "ThreatIntel":
        return cls()

    @classmethod
    def default(cls, extra_paths: Iterable[str] = ()) -> "ThreatIntel":
        """Bundled seed + user config dir + any explicit paths."""
        paths: list[str] = []
        if os.path.isdir(_DATA_DIR):
            paths.append(_DATA_DIR)
        if os.path.isdir(_USER_DIR):
            paths.append(_USER_DIR)
        paths.extend(extra_paths)
        return cls.load(paths)

    @classmethod
    def load(cls, paths: Iterable[str]) -> "ThreatIntel":
        intel = cls()
        for p in paths:
            if os.path.isdir(p):
                for name in sorted(os.listdir(p)):
                    intel._load_file(os.path.join(p, name))
            elif os.path.isfile(p):
                intel._load_file(p)
        return intel

    def _load_file(self, path: str) -> None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            return
        ext = os.path.splitext(path)[1].lower()
        if ext == ".json":
            try:
                data = json.loads(text)
            except (ValueError, json.JSONDecodeError):
                return
            if isinstance(data, dict):
                self._merge(data)
                self.sources.append(path)
        elif ext in (".txt", ".list", ""):
            stem = os.path.splitext(os.path.basename(path))[0].lower()
            key = {"names": "names", "domains": "domains", "hashes": "hashes",
                   "signers": "signers", "packages": "packages"}.get(stem)
            if key:
                entries = [ln.strip() for ln in text.splitlines()
                           if ln.strip() and not ln.startswith("#")]
                self._merge({key: entries})
                self.sources.append(path)

    def _merge(self, data: dict) -> None:
        for n in data.get("names", []) or []:
            self.bad_names.add(_norm_name(n))
        for d in data.get("domains", []) or []:
            self.bad_domains.add(str(d).strip().lower())
        for h in data.get("hashes", []) or []:
            self.bad_hashes.add(str(h).strip().lower())
        for s in data.get("signers", []) or []:
            self.revoked_signers.add(str(s).strip())
        for pkg in data.get("packages", []) or []:
            self.suspect_packages.add(str(pkg).strip().lower().replace("_", "-"))

    def is_empty(self) -> bool:
        return not (self.bad_names or self.bad_domains or self.bad_hashes
                    or self.revoked_signers or self.suspect_packages)

    # ---- matching -------------------------------------------------------- #
    def check(self, artifact: Artifact) -> list[Finding]:
        out: list[Finding] = []
        loc = artifact.metadata.get("manifest_path", artifact.name)

        # 1. Name on the known-malicious list.
        name = str(artifact.metadata.get("declared_name") or artifact.name)
        if _norm_name(name) in self.bad_names:
            out.append(Finding(
                "AFW-IOC-001", "Known-malicious artifact name", Severity.CRITICAL,
                "threat-intel",
                f"'{name}' matches a name on the configured malicious-package feed.",
                path=loc, evidence=name,
                remediation="Do not install; this identifier is flagged as malicious.",
                references=(F.SUPPLY_KNOWN_MALICIOUS, F.LLM03_SUPPLY_CHAIN),
            ))

        # 2. File hash on the known-malicious list.
        for sf in artifact.files:
            if sf.sha256 and sf.sha256.lower() in self.bad_hashes:
                out.append(Finding(
                    "AFW-IOC-002", "Known-malicious file hash", Severity.CRITICAL,
                    "threat-intel",
                    f"'{sf.path}' has a SHA-256 on the malicious-file feed.",
                    path=sf.path, evidence=sf.sha256[:16] + "…",
                    remediation="Do not install; this exact file is flagged as malicious.",
                    references=(F.SUPPLY_KNOWN_MALICIOUS,),
                ))

        # 3b. Depends on / imports a suspect (e.g. AI-hallucinated) package —
        #     "slopsquatting", where attackers register names LLMs invent.
        if self.suspect_packages:
            for sf in artifact.files:
                if sf.is_binary:
                    continue
                for name, lineno in _referenced_packages(sf.text, sf.path):
                    if name.replace("_", "-") in self.suspect_packages:
                        out.append(Finding(
                            "AFW-IOC-005", "Depends on a suspect (slopsquatting) package",
                            Severity.HIGH, "threat-intel",
                            f"'{name}' is on the suspect-package feed (commonly an "
                            "AI-hallucinated name that attackers register). Verify it exists "
                            "and is the intended dependency before installing.",
                            path=sf.path, line=lineno, evidence=name,
                            remediation="Confirm the package is real and correct; pin trusted "
                            "dependencies and remove hallucinated ones.",
                            references=(F.SUPPLY_SLOPSQUATTING, F.SUPPLY_KNOWN_MALICIOUS,
                                        F.LLM03_SUPPLY_CHAIN),
                        ))
                        break  # one per file

        # 3. Contacts a known-malicious domain.
        if self.bad_domains:
            pattern = re.compile(
                r"\b(" + "|".join(re.escape(d) for d in sorted(self.bad_domains)) + r")\b",
                re.IGNORECASE)
            for sf in artifact.files:
                if sf.is_binary:
                    continue
                for lineno, line in enumerate(sf.lines, start=1):
                    m = pattern.search(line)
                    if m:
                        out.append(Finding(
                            "AFW-IOC-003", "Contacts known-malicious domain", Severity.HIGH,
                            "threat-intel",
                            f"References '{m.group(1)}', on the malicious-domain feed.",
                            path=sf.path, line=lineno, evidence=line.strip()[:160],
                            remediation="Remove the call; this destination is flagged as malicious.",
                            references=(F.SUPPLY_KNOWN_MALICIOUS,),
                        ))
                        break  # one per file is enough
        return out

    def check_signer(self, signer: str, artifact: Artifact) -> list[Finding]:
        if signer and signer in self.revoked_signers:
            loc = artifact.metadata.get("manifest_path", artifact.name)
            return [Finding(
                "AFW-IOC-004", "Signed by a revoked identity", Severity.HIGH,
                "threat-intel",
                f"The artifact's signer '{signer}' is on the revoked-signer feed.",
                path=loc, evidence=signer,
                remediation="Treat as untrusted; the signing identity has been revoked.",
                references=(F.SUPPLY_REVOKED_SIGNER, F.SLSA_PROVENANCE),
            )]
        return []
