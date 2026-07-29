"""Provenance detection and trust-tier assignment (Phase 3).

A firewall does not treat every source the same: traffic from a trusted zone is
held to a different bar than traffic from the open internet. AgentFirewall applies
the same idea to artifacts. It looks for **independent provenance** -- signatures,
SLSA/in-toto attestations, SBOMs -- and for a **local trust anchor** (an
``afw.lock`` baseline the user pinned), and from those assigns a
:class:`~agentfirewall.models.TrustTier`.

The tier then feeds policy: an artifact with *no* provenance and no local baseline
is ``UNTRUSTED`` and is held to a stricter bar (see :mod:`agentfirewall.policy`).

Honesty note: detecting that a signature *file exists* is not the same as
*verifying* it. Offline, we can only report presence (tier ``DECLARED``). Real
cryptographic verification requires a verifier and an expected identity; when a
``cosign`` binary is available and ``verify=True`` with an expected identity, we
attempt it and, on success, promote the artifact to ``VERIFIED``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Any, Optional

from . import frameworks as F
from .models import Artifact, Finding, Severity, TrustTier

# Filename signals for each kind of provenance artifact.
_SIG_SUFFIXES = (".sig", ".asc", ".sigstore", ".bundle", ".p7s", ".cosign.bundle")
_SIG_NAMES = ("signature", "cosign.bundle")
_ATTESTATION_SUFFIXES = (".intoto.jsonl", ".att", ".attestation", ".provenance.json")
_ATTESTATION_HINTS = ("provenance", "attestation", "intoto", "in-toto")
_SBOM_SUFFIXES = (".spdx.json", ".spdx", ".cdx.json")
_SBOM_HINTS = ("sbom", "bom.json", "cyclonedx", "spdx")


@dataclass
class Provenance:
    """Everything we could establish about an artifact's provenance."""

    signatures: list[str] = field(default_factory=list)
    attestations: list[str] = field(default_factory=list)
    sboms: list[str] = field(default_factory=list)
    pinned: bool = False
    verified: bool = False
    signer: Optional[str] = None
    tier: TrustTier = TrustTier.UNTRUSTED
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier.label,
            "signed": bool(self.signatures),
            "verified": self.verified,
            "signer": self.signer,
            "attested": bool(self.attestations),
            "sbom": bool(self.sboms),
            "pinned": self.pinned,
            "signatures": self.signatures,
            "attestations": self.attestations,
            "sboms": self.sboms,
            "notes": self.notes,
        }


def detect(artifact: Artifact, pinned: bool = False, verify: bool = False,
           expected_identity: Optional[str] = None) -> Provenance:
    """Inspect ``artifact`` for provenance and compute its trust tier."""
    prov = Provenance(pinned=pinned)

    for sf in artifact.files:
        name = os.path.basename(sf.path).lower()
        if name.endswith(_SIG_SUFFIXES) or any(h in name for h in _SIG_NAMES):
            prov.signatures.append(sf.path)
        elif name.endswith(_ATTESTATION_SUFFIXES) or any(h in name for h in _ATTESTATION_HINTS):
            prov.attestations.append(sf.path)
        elif name.endswith(_SBOM_SUFFIXES) or any(h in name for h in _SBOM_HINTS):
            prov.sboms.append(sf.path)

    # Best-effort signer extraction from a sigstore/JSON bundle.
    if prov.signatures:
        prov.signer = _extract_signer(artifact, prov.signatures)

    # Optional cryptographic verification.
    if verify and prov.signatures:
        ok, signer, note = _verify_with_cosign(artifact, prov, expected_identity)
        prov.verified = ok
        if signer:
            prov.signer = signer
        if note:
            prov.notes.append(note)

    prov.tier = _tier(prov)
    return prov


def _tier(prov: Provenance) -> TrustTier:
    if prov.verified:
        return TrustTier.VERIFIED
    if prov.pinned:
        return TrustTier.PINNED
    if prov.signatures or prov.attestations or prov.sboms:
        return TrustTier.DECLARED
    return TrustTier.UNTRUSTED


def _extract_signer(artifact: Artifact, sig_paths: list[str]) -> Optional[str]:
    by_path = {sf.path: sf for sf in artifact.files}
    for p in sig_paths:
        sf = by_path.get(p)
        if not sf or sf.is_binary or not sf.text.strip():
            continue
        try:
            data = json.loads(sf.text)
        except (ValueError, json.JSONDecodeError):
            continue
        for key in ("identity", "signer", "subject", "certificateIdentity"):
            val = _deep_get(data, key)
            if isinstance(val, str) and val:
                return val
    return None


def _deep_get(obj: Any, key: str) -> Any:
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            found = _deep_get(v, key)
            if found is not None:
                return found
    elif isinstance(obj, list):
        for v in obj:
            found = _deep_get(v, key)
            if found is not None:
                return found
    return None


def _verify_with_cosign(artifact: Artifact, prov: Provenance,
                        expected_identity: Optional[str]) -> tuple[bool, Optional[str], str]:
    """Attempt cosign verification. Returns (verified, signer, note).

    This is best-effort: it only runs when a ``cosign`` binary is on PATH and the
    artifact is a real directory on disk. Without an expected identity we cannot
    make a meaningful trust decision, so we decline rather than claim success.
    """
    if not shutil.which("cosign"):
        return False, None, "signature present but unverified (no cosign binary; " \
                            "run in an environment with cosign to verify)"
    if not os.path.isdir(artifact.root):
        return False, None, "signature present but unverified (artifact not on disk)"
    if not expected_identity:
        return False, None, "signature present but unverified (no --identity given to check against)"

    blob = os.path.join(artifact.root, "artifact.tar")
    sig = os.path.join(artifact.root, prov.signatures[0])
    try:
        res = subprocess.run(
            ["cosign", "verify-blob", "--signature", sig,
             "--certificate-identity", expected_identity, blob],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        return False, None, f"cosign verification errored: {exc}"
    if res.returncode == 0:
        return True, expected_identity, "signature verified with cosign"
    return False, None, "cosign verification FAILED"


# --------------------------------------------------------------------------- #
# Findings derived from provenance state.
# --------------------------------------------------------------------------- #
def findings_for(prov: Provenance, artifact: Artifact) -> list[Finding]:
    loc = artifact.metadata.get("manifest_path", artifact.name)
    out: list[Finding] = []

    if prov.tier is TrustTier.UNTRUSTED:
        out.append(Finding(
            "AFW-PROV-001", "Unsigned, unattested artifact", Severity.INFO,
            "provenance",
            "No signature, attestation, SBOM or local baseline backs this artifact. "
            "It is treated as UNTRUSTED and held to a stricter policy.",
            path=loc, evidence="no provenance found",
            remediation="Pin it with `afw pin` after review, or obtain a signed/attested build.",
            references=(F.SLSA_UNSIGNED, F.LLM03_SUPPLY_CHAIN),
        ))
    elif prov.signatures and not prov.verified:
        out.append(Finding(
            "AFW-PROV-002", "Signature present but not verified", Severity.INFO,
            "provenance",
            "A signature/attestation is present but was not cryptographically verified. "
            + (prov.notes[-1] if prov.notes else "Presence is not proof of validity."),
            path=loc, evidence=", ".join(prov.signatures[:3]),
            remediation="Verify with `--verify-signatures --identity <expected>`.",
            references=(F.SLSA_PROVENANCE,),
        ))
    return out
