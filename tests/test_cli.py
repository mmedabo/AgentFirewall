"""CLI-level tests: exit codes, install gating, output formats."""
import json
import os

import pytest

from agentfirewall.cli import main

EXAMPLES = os.path.join(os.path.dirname(__file__), "..", "examples")


def ex(path):
    return os.path.join(EXAMPLES, path)


def test_scan_safe_exit_zero(capsys):
    assert main(["scan", ex("safe-skill"), "--no-color"]) == 0


def test_scan_malicious_exit_block(capsys):
    assert main(["scan", ex("malicious-skill"), "--no-color"]) == 2


def test_verify_blocks_malicious():
    assert main(["verify", ex("malicious-skill")]) == 2


def test_verify_allows_safe():
    assert main(["verify", ex("safe-skill")]) == 0


def test_scan_json_output(capsys):
    main(["scan", ex("malicious-skill"), "--format", "json"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["verdict"] == "block"
    assert data["findings"]


def test_scan_sarif_output(capsys):
    main(["scan", ex("malicious-skill"), "--format", "sarif"])
    out = capsys.readouterr().out
    data = json.loads(out)
    assert data["version"] == "2.1.0"
    assert data["runs"][0]["results"]


def test_rules_listing(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    assert "AFW-SEC-001" in out


def test_install_blocks_malicious(tmp_path, capsys):
    dest = tmp_path / "installed"
    rc = main(["install", ex("malicious-skill"), "--to", str(dest), "--no-color"])
    assert rc == 2
    assert not (dest / "malicious-skill").exists()


def test_install_allows_safe(tmp_path):
    dest = tmp_path / "installed"
    rc = main(["install", ex("safe-skill"), "--to", str(dest), "--no-color"])
    assert rc == 0
    assert (dest / "safe-skill" / "SKILL.md").exists()


def test_install_force_overrides(tmp_path):
    dest = tmp_path / "installed"
    rc = main(["install", ex("malicious-skill"), "--to", str(dest),
               "--force", "--no-color"])
    assert rc == 0
    assert (dest / "malicious-skill").exists()


def test_watch_once(tmp_path, capsys):
    rc = main(["watch", str(EXAMPLES), "--once", "--interval", "1", "--no-color"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "monitoring" in out.lower()


def test_strict_flag_blocks_medium(tmp_path):
    # safe-skill has no medium+ findings, so strict should still allow it.
    assert main(["verify", ex("safe-skill"), "--strict"]) == 0
