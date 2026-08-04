# AgentFirewall Usage Guide

A task-oriented cookbook for every command. For the big picture see the
[README](../README.md); for internals see [ARCHITECTURE.md](ARCHITECTURE.md).

## Install

```bash
pip install AIAgentFirewall        # from PyPI (once published); import stays `agentfirewall`
# or from source:
git clone https://github.com/mmedabo/agentfirewall && cd agentfirewall && pip install -e .
```

Installs the `afw` command (alias `agentfirewall`). Or run without installing:
`python -m agentfirewall …`. No dependencies are required.

## The mental model

AgentFirewall works in four layers; reach for the one that fits your moment:

| Moment | Command |
|---|---|
| "Should I install this?" | `afw scan` / `afw verify` / `afw install` |
| "Did this update sneak something in?" | `afw pin` then `afw scan --baseline` |
| "How much do I trust the source?" | trust tiers + `--intel` (built into every scan) |
| "Contain it while it runs." | `afw run` (egress) / `afw mcp-proxy` (tool calls) |
| "I'd rather click than type." | `afw serve` |

---

## Scanning

### Look at something before installing it

```bash
afw scan ./some-skill              # human-readable report + verdict
afw scan ./a.zip ./b/ ./c.md       # scan several artifacts at once
afw scan ./skill -v                # -v adds remediation guidance
```

Exit codes: `0` allow/warn, `2` block, `1` error — so `afw scan` works in a
shell `if`.

### Gate a CI pipeline

```bash
afw verify ./my-skill                       # exit 2 if BLOCK
afw verify ./my-skill --fail-on-warn        # also fail on WARN
afw verify ./my-skill --format sarif > out.sarif   # upload to code scanning
```

### Install only if it passes

```bash
afw install ./some-skill --to ~/.claude/skills
#   ⛔ BLOCKED → nothing is copied.  Clean artifact → copied normally.
afw install ./some-skill --to ~/.claude/skills --force   # override (dangerous)
```

### Output formats

`--format text` (default, colourised), `--format json` (the `ScanResult` schema),
`--format sarif` (GitHub code-scanning / CI dashboards).

---

## Tuning what blocks (policy)

```bash
afw scan ./skill --strict                    # block on MEDIUM and above
afw scan ./skill --fail-on CRITICAL          # only block on CRITICAL
afw scan ./skill --ignore AFW-PERM-002       # suppress a rule (or a category)
afw scan ./skill --policy policy.yaml        # load a policy file
```

`policy.yaml`:

```yaml
block_severity: HIGH          # INFO | LOW | MEDIUM | HIGH | CRITICAL
warn_severity: LOW
ignore: [AFW-PERM-002]
warn_only_categories: [install-hook]
tighten_untrusted: true       # stricter bar for unsigned/unpinned artifacts
```

---

## Catching rug pulls (baselining)

The attack static scanning can't see: an artifact that's clean today and malicious
after an update. Pin what you approved, then re-check every update.

```bash
afw pin ./some-skill                                   # writes ./some-skill/afw.lock
# … the author ships an update …
afw scan ./some-skill --baseline ./some-skill/afw.lock
#   ✗ CRITICAL  Tool grant added since baseline     [AFW-DRIFT-010]
#     HIGH      Baselined file changed              [AFW-DRIFT-001]
```

A changed file, a new tool grant, or a mutated tool description all raise
`AFW-DRIFT-*`. Store the lock file where the artifact can't rewrite it, and re-pin
only after reviewing the diff. `pin` refuses to baseline a currently-BLOCKED
artifact unless you pass `--force`.

---

## Trust tiers & threat intel

Every scan reports a **trust tier** from the artifact's provenance:

```
UNTRUSTED  no signature / attestation / baseline   → policy tightens one level
DECLARED   signature or SBOM present (unverified)
PINNED     you hold a local afw.lock                (afw pin)
VERIFIED   signature cryptographically verified      (--verify-signatures)
```

```bash
afw scan ./skill                                  # see its tier
afw scan ./skill --no-tighten-untrusted           # don't penalise unsigned
afw scan ./skill --verify-signatures --identity maintainer@example.com
```

**Threat-intel feeds** match name, file hash, contacted domain and signer identity
against IoC lists (offline by default):

```bash
afw scan ./skill --intel ./my-iocs/               # add feeds (JSON or txt)
afw scan ./skill --no-intel                        # disable the bundled seed
```

Feed formats — JSON `{"names":[],"domains":[],"hashes":[],"signers":[]}`, or plain
text files named `names.txt` / `domains.txt` / `hashes.txt` / `signers.txt`. Drop
your own into `~/.config/agentfirewall/intel/` to load them automatically.

---

## Runtime firewall

### Contain outbound traffic — `afw run`

Run any command with a default-deny egress allowlist:

```bash
afw run --allow "*.github.com" -- npx some-agent
#   BLOCK HTTP    evil.example:80
#   ALLOW HTTP    api.github.com:443
afw run --allow api.github.com --allow-port 443 --fail-on-egress -- ./tool
```

Only allowlisted hosts get through; everything else gets a `403` and is logged.
`--fail-on-egress` exits non-zero if anything was blocked (useful in CI).
`--allow-loopback` permits localhost. The proxy also applies **outbound DLP**: a
plaintext-HTTP request carrying a secret (private key, AWS/GitHub/provider token)
is blocked *even to an allowlisted host* (HTTPS bodies stay opaque).

> Enforcement is proxy-based: it governs clients honouring `HTTP(S)_PROXY` (most
> HTTP libraries and CLIs). For bypass-proof containment, use `--isolate` below.

### Run something with *zero* network — `afw run --isolate`

For untrusted install hooks / setup scripts, cut off the network entirely at the
kernel level:

```bash
afw run --isolate -- bash setup.sh
#   method  : unshare (root netns)
#   network : DENIED (kernel-enforced; no external connectivity)
```

The command runs in a fresh network namespace with no external interface, so it
**physically cannot reach any host** — even via raw sockets, even as root inside.
Loopback still works; if the host can't create a namespace it refuses rather than
running unprotected. Uses `unshare` or `bubblewrap`.

### Bypass-proof *allowlisting* — `afw run --isolate --allow`

The strongest mode: reach these hosts and nothing else, and the process can't
escape it.

```bash
afw run --isolate --allow "*.github.com" -- npx some-agent
#   ALLOW HTTP  api.github.com:443      ← brokered out
#   (anything off the allowlist, or any raw socket, gets no network)
```

The command runs in a no-IP namespace; its egress is brokered through a
Unix-domain-socket filtering proxy in the parent (a UDS crosses the namespace
boundary, IP traffic can't). So the broker enforces the allowlist while a raw
socket that ignores the proxy simply fails. `--fail-on-egress` still applies.

Three strengths to choose from:

| Command | Enforcement | Governs |
|---|---|---|
| `afw run --allow H -- cmd` | proxy allowlist | clients honouring `HTTP(S)_PROXY` |
| `afw run --isolate -- cmd` | zero network | everything (bypass-proof) |
| `afw run --isolate --allow H -- cmd` | allowlist | everything (bypass-proof) |

### Inspect an MCP server's tool calls — `afw mcp-proxy`

Sit between the agent and an MCP server, inspecting every JSON-RPC message:

```bash
afw mcp-proxy -- npx some-mcp-server               # default: block severe findings
afw mcp-proxy --action redact -- python server.py  # redact instead of block
afw mcp-proxy --action warn -- ./server            # log only, forward everything
```

It catches **tool poisoning** in `tools/list` descriptions, **secret egress** in
`tools/call` arguments, and **injected instructions** in tool results — then
forwards, redacts, or blocks. Point your MCP client at `afw mcp-proxy -- <server>`
in place of the raw server command; findings are logged to stderr so stdout stays
a clean JSON-RPC channel.

---

## The web UI — `afw serve`

Prefer clicking to typing? Launch the local web app:

```bash
afw serve                # http://127.0.0.1:8000
afw serve --open         # also open a browser
afw serve --port 9000
```

Drag-drop a skill folder or `.zip` (or type a path), toggle strict / threat-intel,
and read the verdict, trust tier, severity breakdown and each finding with its
evidence, framework tags and remediation. It runs entirely locally, binds to
loopback, and the JSON API is protected by a per-run token so no other site in your
browser can drive it. Nothing you scan is uploaded anywhere or executed.

---

## Discovering detections

```bash
afw rules                 # every detection: id, severity, category, framework coverage
afw rules --format json   # machine-readable catalogue
```

---

## Using it from Python

```python
from agentfirewall import Scanner, Policy, Verdict
from agentfirewall.intel import ThreatIntel

scanner = Scanner(policy=Policy.strict(), intel=ThreatIntel.default())
result = scanner.scan_path("./some-skill")

print(result.verdict, result.trust_tier)
for f in result.findings:
    print(f.severity.label, f.rule_id, f.location(), f.message)

if result.verdict is Verdict.BLOCK:
    raise SystemExit("refusing to install")
```

## Guardrails for agents you deploy (Python library)

Static scan finds the deployed-agent bugs; `agentfirewall.guardrails` *enforces* the
fix at request time.

```python
from agentfirewall.guardrails import (
    InputGuard, ScopePolicy, PreconditionGate, InMemoryQuota, QuotaExceeded,
)

# Confine the agent to its business tools; deny code execution + injection.
guard = InputGuard(ScopePolicy.for_tools("search_menu", "place_order"))
# Authorize + reserve quota before the agent runs, idempotent by request id.
gate = PreconditionGate(InMemoryQuota(balances={"user-1": 5}))

def handle_chat(user_id, prompt, request_id):
    guard.check_input(prompt).raise_if_blocked()
    try:
        return gate.run(user_id, lambda: agent.run(prompt), idempotency_key=request_id)
    except QuotaExceeded:
        return {"error": "out of credits"}, 402

# In your model's tool-dispatch hook, gate every tool call:
def before_tool_call(name, arguments):
    guard.check_tool_call(name, arguments).raise_if_blocked()   # blocks run_python etc.
```

**Taint / provenance (indirect prompt-injection defense).** Wrap data that comes
from outside the trust boundary — tool outputs, retrieved documents, other agents'
messages — with `taint()`, and the guard refuses to let it drive a *sensitive*
tool (code exec, send/email, http, sql, file write, payments…):

```python
from agentfirewall.guardrails import taint

retrieved = taint(vector_store.query(q))          # untrusted-derived
guard.check_tool_call("send_email", {"body": retrieved}).raise_if_blocked()  # BLOCKED
guard.check_tool_call("search_menu", {"q": retrieved})                       # allowed (benign tool)
```

Tune with `ScopePolicy(taint_sensitive_sinks=…, deny_tainted_to={"pay", "transfer"})`,
or pass `tainted=True` explicitly. This is the CaMeL-style "untrusted data must not
drive consequential actions" defense against indirect prompt injection.

- `PreconditionGate.run` consumes quota **atomically before** the action and returns
  the cached result on a **replay** with the same `idempotency_key` — so a page
  refresh can't burn free tokens (the Bolt.new exploit) and a zero-quota user never
  reaches the agent. Failed actions are refunded. There's also a `@gate.guard()`
  decorator.
- `InputGuard` denies tool calls outside the allowlist or that run code/shell, and
  rejects prompt-injection / exfiltration in input and tool arguments.
- The bundled `InMemoryQuota` / `InMemoryIdempotencyStore` are single-process
  references; back them with Redis or a database in production (same interface).

The runtime *host-side* pieces are importable too:

```python
from agentfirewall.runtime.egress import EgressPolicy
from agentfirewall.runtime.sandbox import run_guarded

report = run_guarded(["curl", "https://evil.example"],
                     EgressPolicy.from_spec(["*.github.com"]))
print(report.blocked())      # [BLOCK CONNECT evil.example:443]
```
