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

### Still open (Phase 5.x)

- **Bypass-proof *allowlisting*** (reach these hosts, nothing else — enforced by
  the kernel, not a proxy) needs a userspace network stack (`slirp4netns`) or
  root + `ip`/NAT to route the namespace through the filtering proxy. Until then,
  use `--isolate` for zero-network or `--allow` (Phase 4 proxy) for allowlisting.
- Deeper **seccomp / Landlock** filesystem confinement without bubblewrap.

## How to help

New detections are usually a one-line signature — see
[CONTRIBUTING.md](../CONTRIBUTING.md). Detection bypasses are tracked as bugs; see
[SECURITY.md](../SECURITY.md).
