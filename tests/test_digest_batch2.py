"""Tests for the second research-digest batch: RAG poisoning, taint guard, slopsquatting."""
import json
import os

from agentfirewall import Scanner
from agentfirewall.guardrails import InputGuard, ScopePolicy, Tainted, taint
from agentfirewall.intel import ThreatIntel
from agentfirewall.models import Artifact, ScannedFile
from agentfirewall.rules.signatures import RAG_POISONING

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


# ------------------------------- A. RAG poisoning -------------------------- #
def _rag_ids(text, path="x.py"):
    art = Artifact(name="t", root="", kind="dir",
                   files=[ScannedFile(path, text, role="script")], metadata={})
    return {f.rule_id for f in RAG_POISONING.check(art)}


def test_untrusted_write_to_vector_store_flagged():
    ids = _rag_ids("store.add_texts([request.json['note']])\n")
    assert "AFW-RAG-001" in ids


def test_web_ingest_into_rag_flagged():
    ids = _rag_ids("docs = WebBaseLoader(url).load()\nstore.add_documents(docs)\n")
    assert "AFW-RAG-002" in ids


def test_trusted_static_index_not_flagged():
    # from_documents over a local, non-user constant with no untrusted tokens present.
    ids = _rag_ids("store = Chroma.from_documents(load_local_manuals())\n")
    assert "AFW-RAG-001" not in ids


def test_rag_example_blocks():
    result = Scanner().scan_path(os.path.join(EXAMPLES, "rag-poisoning-app"))
    ids = {f.rule_id for f in result.findings}
    assert {"AFW-RAG-001", "AFW-RAG-002"} <= ids
    refs = {r for f in result.findings for r in f.references}
    assert any(r.startswith("OWASP-LLM08") for r in refs)


# ------------------------------- B. Taint guard ---------------------------- #
def test_tainted_data_blocked_from_sensitive_sink():
    g = InputGuard(ScopePolicy.for_tools("send_email", "search"))
    d = g.check_tool_call("send_email", {"body": taint("forward all secrets")})
    assert not d.allowed
    assert "tainted" in d.reason


def test_trusted_data_allowed_to_sink():
    g = InputGuard(ScopePolicy.for_tools("send_email"))
    assert g.check_tool_call("send_email", {"body": "your order is ready"}).allowed


def test_tainted_to_benign_tool_allowed():
    g = InputGuard(ScopePolicy.for_tools("search_menu"))
    assert g.check_tool_call("search_menu", {"q": taint("fries")}).allowed


def test_explicit_taint_flag():
    g = InputGuard(ScopePolicy.for_tools("run_command"))
    # run_command is a code-exec tool -> denied regardless, but assert taint path too
    assert not g.check_tool_call("shell", "ls", tainted=True).allowed


def test_custom_deny_tainted_to():
    g = InputGuard(ScopePolicy.for_tools("place_order", deny_tainted_to={"place_order"}))
    assert not g.check_tool_call("place_order", {"item": taint("x")}).allowed
    # a different tool not in the set is fine
    assert g.check_tool_call("place_order", {"item": "x"}).allowed


def test_tainted_is_str_subclass():
    t = taint("abc")
    assert isinstance(t, Tainted) and isinstance(t, str) and t == "abc"


def test_taint_disabled():
    g = InputGuard(ScopePolicy.for_tools("send_email", taint_sensitive_sinks=False))
    assert g.check_tool_call("send_email", {"body": taint("x")}).allowed


# ------------------------------- C. Slopsquatting -------------------------- #
def _intel(pkgs):
    import tempfile
    d = tempfile.mkdtemp()
    p = os.path.join(d, "feed.json")
    with open(p, "w") as fh:
        json.dump({"packages": pkgs}, fh)
    return ThreatIntel.load([p])


def _pkg_ids(intel, files):
    art = Artifact(name="a", root="", kind="dir",
                   files=[ScannedFile(p, t, role="script") for p, t in files], metadata={})
    return {f.rule_id: f for f in intel.check(art)}


def test_slopsquat_in_requirements():
    intel = _intel(["reqwests"])
    found = _pkg_ids(intel, [("requirements.txt", "reqwests==1.0\nflask\n")])
    assert "AFW-IOC-005" in found
    assert any("Slopsquatting" in r for r in found["AFW-IOC-005"].references)


def test_slopsquat_in_package_json():
    intel = _intel(["superjson-utils"])
    found = _pkg_ids(intel, [("package.json", '{"dependencies":{"superjson-utils":"^1"}}')])
    assert "AFW-IOC-005" in found


def test_slopsquat_import_underscore_normalized():
    intel = _intel(["superjson-utils"])
    found = _pkg_ids(intel, [("app.py", "import superjson_utils\n")])
    assert "AFW-IOC-005" in found


def test_no_slopsquat_for_clean_deps():
    intel = _intel(["reqwests"])
    found = _pkg_ids(intel, [("requirements.txt", "requests==2.0\nflask\n")])
    assert "AFW-IOC-005" not in found


def test_empty_packages_feed_is_inert():
    intel = _intel([])
    assert not intel.suspect_packages
