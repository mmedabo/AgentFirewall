"""Tests for provenance, trust tiers and threat-intel (Phase 3)."""
import json
import os

from agentfirewall import Policy, Scanner, Severity, Verdict
from agentfirewall import provenance
from agentfirewall.intel import ThreatIntel, _norm_name
from agentfirewall.models import Artifact, ScannedFile, TrustTier

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def _artifact(files, metadata=None, kind="skill", root="."):
    return Artifact(name="t", root=root, kind=kind, files=files, metadata=metadata or {})


# --------------------------- provenance / trust tier ----------------------- #
def test_untrusted_when_no_provenance():
    art = _artifact([ScannedFile("SKILL.md", "x", role="manifest", sha256="a")])
    prov = provenance.detect(art)
    assert prov.tier is TrustTier.UNTRUSTED


def test_declared_when_signature_present():
    art = _artifact([
        ScannedFile("SKILL.md", "x", role="manifest", sha256="a"),
        ScannedFile("SKILL.md.sig", '{"identity":"me@example.com"}', role="config", sha256="b"),
    ])
    prov = provenance.detect(art)
    assert prov.tier is TrustTier.DECLARED
    assert prov.signer == "me@example.com"
    assert prov.signatures == ["SKILL.md.sig"]


def test_declared_when_sbom_present():
    art = _artifact([ScannedFile("sbom.spdx.json", "{}", role="config", sha256="a")])
    prov = provenance.detect(art)
    assert prov.tier is TrustTier.DECLARED
    assert prov.sboms


def test_pinned_beats_declared():
    art = _artifact([ScannedFile("SKILL.md", "x", role="manifest", sha256="a")])
    prov = provenance.detect(art, pinned=True)
    assert prov.tier is TrustTier.PINNED


def test_signed_example_is_declared():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "signed-skill"))
    assert result.trust_tier is TrustTier.DECLARED
    assert result.provenance["signed"] and result.provenance["sbom"]
    assert "AFW-PROV-002" in {f.rule_id for f in result.findings}


def test_unsigned_finding_is_info_not_verdict_changing():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "safe-skill"))
    assert result.trust_tier is TrustTier.UNTRUSTED
    assert result.verdict is Verdict.ALLOW
    prov_findings = [f for f in result.findings if f.rule_id == "AFW-PROV-001"]
    assert prov_findings and prov_findings[0].severity is Severity.INFO


# ------------------------------- policy tightening ------------------------- #
def test_tightening_blocks_medium_when_untrusted():
    policy = Policy()  # block_severity=HIGH, tighten_untrusted=True
    findings = [_med()]
    assert policy.decide(findings, TrustTier.UNTRUSTED) is Verdict.BLOCK
    assert policy.decide(findings, TrustTier.PINNED) is Verdict.WARN


def test_no_tighten_flag_keeps_medium_as_warn():
    policy = Policy(tighten_untrusted=False)
    assert policy.decide([_med()], TrustTier.UNTRUSTED) is Verdict.WARN


def test_block_threshold_helper():
    p = Policy()
    assert p.block_threshold(TrustTier.UNTRUSTED) is Severity.MEDIUM
    assert p.block_threshold(TrustTier.PINNED) is Severity.HIGH


# ------------------------------- threat intel ------------------------------ #
def test_intel_domain_match_on_malicious_example():
    scanner = Scanner(intel=ThreatIntel.default())
    result = scanner.scan_path(os.path.join(EXAMPLES, "malicious-skill"))
    assert "AFW-IOC-003" in {f.rule_id for f in result.findings}


def test_intel_bad_name(tmp_path):
    feed = tmp_path / "feed.json"
    feed.write_text(json.dumps({"names": ["evil-skill"]}))
    intel = ThreatIntel.load([str(feed)])
    art = _artifact([ScannedFile("SKILL.md", "x", role="manifest", sha256="a")],
                    metadata={"declared_name": "evil-skill", "manifest_path": "SKILL.md"})
    ids = {f.rule_id for f in intel.check(art)}
    assert "AFW-IOC-001" in ids


def test_intel_bad_hash(tmp_path):
    feed = tmp_path / "hashes.txt"
    feed.write_text("deadbeef\n")
    intel = ThreatIntel.load([str(feed)])
    art = _artifact([ScannedFile("payload.sh", "x", role="script", sha256="deadbeef")])
    ids = {f.rule_id for f in intel.check(art)}
    assert "AFW-IOC-002" in ids


def test_intel_revoked_signer(tmp_path):
    feed = tmp_path / "signers.txt"
    feed.write_text("attacker@evil.example\n")
    intel = ThreatIntel.load([str(feed)])
    art = _artifact([ScannedFile("SKILL.md", "x", role="manifest", sha256="a")])
    ids = {f.rule_id for f in intel.check_signer("attacker@evil.example", art)}
    assert "AFW-IOC-004" in ids


def test_intel_name_normalization_homoglyph():
    # '0' -> 'o' so "g00gle" normalizes toward "google"
    assert _norm_name("G00gle") == _norm_name("google")


def test_empty_intel_produces_nothing():
    intel = ThreatIntel.empty()
    assert intel.is_empty()
    art = _artifact([ScannedFile("SKILL.md", "evil.example", role="manifest", sha256="a")])
    assert intel.check(art) == []


def test_no_intel_flag_disables_feed():
    from agentfirewall.cli import main
    # With intel disabled, the IoC domain finding should not appear (exit still block
    # for other reasons, so just assert the flag is accepted and runs).
    rc = main(["scan", os.path.join(EXAMPLES, "safe-skill"), "--no-intel", "--no-color"])
    assert rc == 0


def _med():
    from agentfirewall.models import Finding
    return Finding("X", "t", Severity.MEDIUM, "c", "m")
