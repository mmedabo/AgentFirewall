# AgentFirewall Roadmap

AgentFirewall is built to mirror a real firewall stack: stateless filtering,
stateful inspection, egress control, and an application-layer proxy. We are
working through those layers in defence-in-depth order.

See [THREAT-MODEL.md](THREAT-MODEL.md) for how each layer maps to firewall
mechanics and security frameworks.

## ✅ Phase 0 — Static scanner (shipped)

The stateless "packet filter" layer.

- Signature + structural rule engine over directories, files and zip archives.
- Detections for secret access, exfiltration, obfuscation/dynamic-exec,
  destructive actions, sensitive-file reads, prompt injection, hidden unicode,
  encoded blobs, permission overreach and install hooks.
- `scan` / `verify` (CI gate) / `install` (pre-check gate) / `watch` / `rules`.
- Policy engine (ALLOW / WARN / BLOCK), text / JSON / SARIF output.

## ✅ Phase 1 — Framework-mapped detection expansion (shipped)

Every detection now cites OWASP LLM, OWASP Agentic, MITRE ATLAS, MCP or
supply-chain identifiers, and `afw rules` reports live coverage. New detections:

- **Embedded credentials** shipped inside artifacts — `AFW-KEY-*` (OWASP LLM02).
- **Unsafe deserialization / model poisoning** — `AFW-DSR-*` (LLM04).
- **Improper output handling** (model output → sink) — `AFW-OUT-*` (LLM05).
- **Tool poisoning** — hidden directives in tool/MCP descriptions — `AFW-TPZ-*`
  and **MCP env secrets / auto-approve** — `AFW-MCP-*`.
- **Memory / context poisoning** — writes to agent instruction/config files —
  `AFW-MEM-*` (OWASP Agentic).
- **Anti-forensics / repudiation** — history & log tampering — `AFW-AF-*`.
- **Typosquatting / homoglyph impersonation** — `AFW-SQT-*` (supply chain).

## ✅ Phase 2 — Stateful baselining / rug-pull defense (shipped)

The "stateful inspection" layer: remember an artifact's approved shape and flag
drift.

- `afw pin` writes `afw.lock` (per-file hashes + declared tool/permission/MCP/
  description surface).
- `--baseline` on `scan` / `verify` / `install` diffs against the lock and raises
  `AFW-DRIFT-*` findings; a silently added tool grant is `CRITICAL`.
- Defeats **rug pulls** and insider updates (e.g. Postmark 2025) that static
  analysis alone cannot see.

## ✅ Phase 3 — Provenance & trust zoning (shipped)

The "threat-intel + segmentation" layer.

- **Provenance detection**: finds signatures, SLSA/in-toto attestations and SBOMs,
  extracts the signer identity, and assigns a **trust tier**
  (`UNTRUSTED` → `DECLARED` → `PINNED` → `VERIFIED`). Optional cryptographic
  verification via `cosign` (`--verify-signatures --identity <expected>`).
- **Trust-aware policy**: `UNTRUSTED` artifacts (no signature, attestation or local
  baseline) are held to a stricter bar — the block threshold tightens by one
  severity level. `afw pin` raises an artifact to `PINNED`; `--no-tighten-untrusted`
  opts out. Every scan reports the tier and provenance summary.
- **Threat-intel / IoC feeds** (`AFW-IOC-*`): match artifact name, file SHA-256,
  contacted domains and signer identity against pluggable, **offline-by-default**
  feeds (JSON or `names.txt`/`domains.txt`/`hashes.txt`/`signers.txt`). A bundled
  seed ships as a starting point; add your own with `--intel <path>` or
  `~/.config/agentfirewall/intel/`.

## ✅ Phase 4 — Runtime firewall (shipped)

The "egress filter + WAF" layer — watching an agent and its tools *while they run*.

- **Egress firewall** (`afw run`): runs a command with its outbound HTTP(S) wired
  through a **default-deny filtering proxy** (`EgressProxy`). Only allowlisted hosts
  (`--allow *.github.com`) get through; everything else gets a `403`, and every
  attempt is logged. `--fail-on-egress` turns a blocked connection into a non-zero
  exit for CI.
- **MCP tool-call proxy** (`afw mcp-proxy -- <server>`): sits between the agent and
  an MCP server over stdio and inspects every JSON-RPC message — `tools/list`
  descriptions (tool poisoning), `tools/call` arguments (secret egress / injected
  content), and tool results (injected instructions / DLP) — then **forwards,
  redacts, or blocks** in real time.

**Enforcement scope (honest):** egress control is proxy-based — it governs any
client that honours `HTTP(S)_PROXY` (most HTTP libraries and CLIs). A process that
opens raw sockets and ignores the proxy env is not contained by this layer alone.

## ✅ Phase 5 — Bypass-proof isolation (shipped)

Harden the runtime layer against determined evasion.

- **Kernel-enforced network isolation** (`afw run --isolate`): runs a command in a
  fresh **network namespace** with no external interface, so it physically cannot
  reach any host — even via raw sockets, even as root inside the namespace. This
  closes the raw-socket bypass for the most important case: running untrusted
  install hooks / setup scripts with **zero network**. Backends: `unshare`
  (root or rootless user namespace), or **bubblewrap** when installed (which adds
  filesystem + seccomp confinement). If the host can't isolate, `--isolate`
  **refuses** rather than silently running with full network.
- Loopback is brought up inside the jail, so isolated processes can still use
  `localhost` if they need it.

### ✅ Phase 5.5 — Bypass-proof allowlisting (shipped)

`afw run --isolate --allow <host>` now enforces an allowlist that a process
**cannot escape** — reach these hosts, nothing else, kernel-enforced. It runs the
command in a network namespace with no IP connectivity and brokers its egress
through a **Unix-domain-socket filtering proxy** in the parent (a UDS crosses the
namespace boundary because it's filesystem-based, not IP-based). A process that
ignores the proxy and opens a raw socket simply gets no network, so the broker's
allowlist is the only way out. No external dependencies — pure `unshare` + stdlib.

### Still open (Phase 5.x)

- Deeper **seccomp / Landlock** filesystem + syscall confinement without
  bubblewrap (today, install `bwrap` to get it under `--isolate`).

## ✅ Phase 6 — Deployed-agent guardrails (shipped: static)

A new *direction*: protect an agent **you ship** from abuse by its own users, not
just protect your host from an artifact you install. Static detections for the two
classes seen in the wild:

- **Excessive agency / no scoping** (`AFW-AGENCY-*`): user input driving code
  execution, a code/shell tool exposed to end users, or a system prompt that grants
  unrestricted scope (the "food bot runs Python" case). OWASP LLM06.
- **Broken authorization** (`AFW-AUTHZ-*`): the agent invoked *before* the
  quota/authz check (check-after-act TOCTOU — the Bolt.new refresh exploit), or a
  limit enforced only client-side. CWE-367, OWASP API BFLA, LLM10.

Run `afw scan ./my-agent-app`; see `examples/vulnerable-agent-app`.

### 🔜 Phase 6.1 — Runtime guardrail library (planned)

An embeddable guardrail developers wire into their agent to *enforce* the above at
request time, not just detect it in code:

- a **scope policy** (allowed intents/capabilities; deny code execution / off-topic
  requests), reusing the rule engine on the user's input;
- a **precondition gate** that authorizes and atomically reserves quota *before* the
  agent runs, with idempotency-by-request-id so a refresh/replay can't slip through.

## How to help

New detections are usually a one-line signature — see
[CONTRIBUTING.md](../CONTRIBUTING.md). Detection bypasses are tracked as bugs; see
[SECURITY.md](../SECURITY.md).
