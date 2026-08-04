# Changelog

All notable changes to AgentFirewall are documented here. This project follows
[Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [1.3.1] — Packaging: PyPI name

First release published to PyPI under the distribution name **`AIAgentFirewall`**
(the `agentfirewall` name was already claimed on PyPI by an unrelated project). The
import module (`agentfirewall`) and the CLI (`afw` / `agentfirewall`) are unchanged;
this is a packaging-only bump so the wheel/sdist metadata and the release tag carry
the new distribution name. Install with `pip install AIAgentFirewall`.

## [1.3.0] — Inter-agent security + outbound DLP

Third research batch — the lower-priority items, now grounded in fresh 2026 research.

- **Insecure inter-agent / A2A** (`AFW-A2A-001/002`, OWASP ASI07 + ASI03): flags an
  A2A agent card advertising skills with **no authentication scheme**, and code that
  **disables inter-agent signature/identity verification** (`verify_signature=False`,
  `trust_all_agents`) — the impersonation / card-shadowing class.
- **Outbound-content DLP** in the egress firewall: `afw run` now blocks a
  plaintext-HTTP request that carries a secret (private key, AWS/GitHub/Slack/
  provider token) **even to an allowlisted host** (`EgressPolicy.dlp_scan_bodies`,
  on by default; HTTPS bodies remain opaque).
- New `examples/insecure-a2a`; README version badge corrected.

## [1.2.0] — Research-driven detections, batch 2

Second batch from the research scout — RAG poisoning, a taint guard, slopsquatting.

- **RAG / vector-store poisoning** (`AFW-RAG-001/002`, OWASP LLM08 + ASI06): flags
  untrusted/user-derived content written into a shared vector store or knowledge
  base, and unvalidated web documents indexed for retrieval (~5 poisoned docs can
  steer 90% of responses).
- **Taint / provenance guard** (CaMeL-style): `agentfirewall.guardrails` gains
  `Tainted` / `taint()` and a `ScopePolicy` taint gate — untrusted-derived data is
  refused from reaching sensitive tool sinks (code exec, send/email, http, sql,
  file write, payments…). Defends against indirect prompt injection, the dominant
  2026 attack. Configurable via `taint_sensitive_sinks` / `deny_tainted_to`.
- **Slopsquatting** (`AFW-IOC-005`): the threat-intel feed gains a `packages` list;
  scans imports / `requirements.txt` / `package.json` deps for suspect
  AI-hallucinated package names (opt-in feed; the shipped seed is empty on purpose).
- New `examples/rag-poisoning-app`.

## [1.1.0] — Research-driven detections

First batch of adaptations from the daily research scout (2026-08-03 digest):

- **Official OWASP Agentic ASI01–ASI10 IDs.** Framework references now use the
  finalized identifiers from the OWASP Top 10 for Agentic Applications 2026 (e.g.
  `OWASP-ASI06:Memory-and-Context-Poisoning`); code-execution findings also cite
  `OWASP-ASI05`. Back-compat aliases retained.
- **`AFW-MCP-003` — remote MCP server without authentication.** Flags MCP clients
  configured to reach a remote server (http/sse) with no auth header/token, and
  plaintext `http://` endpoints — the class behind the 2026 MCP CVEs and the 400+
  publicly-exposed, unauthenticated MCP servers.
- **`AFW-NET-007` — auto-fetched image/link with a dynamic URL.** Detects the
  zero-click exfiltration channel used by EchoLeak (CVE-2025-32711): reference-style
  markdown images / `<img>` tags that auto-load an external URL carrying data.
- New `examples/insecure-mcp` fixture.

## [1.0.0] — First stable release

First stable, feature-complete release. AgentFirewall now spans the full agent
security lifecycle, in two directions:

**Inbound — trust an artifact before you install it**
- Static scanner (skills, agents, MCP servers, plugins; dir/file/zip) with 50+
  detections across secrets, exfiltration, obfuscation, destructive actions,
  prompt injection, tool poisoning, memory poisoning, typosquatting and more —
  every finding mapped to OWASP LLM / OWASP Agentic / MITRE ATLAS / MCP / SLSA.
- Stateful rug-pull defense (`afw pin` / `--baseline`), trust tiers from provenance,
  and offline threat-intel feeds.
- `scan` / `verify` / `install` gates; text / JSON / SARIF; a local web UI
  (`afw serve`); a reusable GitHub Action.

**Runtime — contain what runs**
- Egress firewall (`afw run --allow`), MCP tool-call proxy (`afw mcp-proxy`),
  kernel network-jail (`afw run --isolate`), and bypass-proof allowlisting
  (`afw run --isolate --allow`).

**Outbound — harden the agents you deploy**
- Static guardrail detections (`AFW-AGENCY-*`, `AFW-AUTHZ-*`) and the embeddable
  `agentfirewall.guardrails` library (`PreconditionGate`, `InputGuard`).

No changes to the public API since 0.9.0; this release marks stability, bumps the
package to Production/Stable, and is the first tagged/published version.

## [0.9.0] — Runtime guardrail library

- `agentfirewall.guardrails`: embeddable enforcement for deployed agents.
  - **`PreconditionGate`**: authorize + atomically reserve quota *before* the agent
    runs, idempotent by request id (a refresh/replay returns the cached result
    instead of re-running/charging) — the fix for the Bolt.new refresh exploit.
    Refunds on failure; ships reference in-memory quota/idempotency stores.
  - **`InputGuard` / `ScopePolicy`**: confine an agent to a tool allowlist, deny
    code/shell tools, and reject prompt-injection/exfiltration in input and tool
    arguments (reuses the rule engine).
- New `examples/guarded-agent-app` (the vulnerable example, fixed).

## [0.8.0] — Deployed-agent guardrails

- New protection *direction*: harden an agent **you deploy**, not just artifacts you
  install. Static detections for two real-world abuse classes:
  - **Excessive agency** (`AFW-AGENCY-*`): user input driving code execution, a
    code/shell tool exposed to end users, or an unrestricted-scope system prompt
    (the "food-ordering bot runs Python" case). OWASP LLM06.
  - **Broken authorization** (`AFW-AUTHZ-*`): the agent invoked before the
    quota/authz check (check-after-act TOCTOU — the Bolt.new refresh exploit), or a
    limit enforced only client-side. CWE-367, OWASP API BFLA, LLM10.
- New `examples/vulnerable-agent-app` fixture; framework refs for OWASP API Security
  and CWE-367/602.

## [0.7.0] — Bypass-proof allowlisting

- **`afw run --isolate --allow <host>`**: reach these hosts and nothing else,
  kernel-enforced. Runs in a no-IP network namespace whose egress is brokered
  through a Unix-domain-socket filtering proxy (a UDS crosses the namespace
  boundary; IP traffic can't), so a process that ignores the proxy and opens a raw
  socket simply gets no network. Pure `unshare` + stdlib, no external deps.
- `EgressProxy` can now listen on a Unix socket; `runtime/_jailrun.py` supervises
  the in-namespace loopback + TCP→UDS forwarder.
- Packaging (from 0.6.x): reusable GitHub Action (`action.yml`) and a tag-triggered
  release workflow that publishes to PyPI via Trusted Publishing.

## [0.6.0] — Bypass-proof isolation

- **`afw run --isolate`**: run a command in a kernel network namespace with no
  external interface — bypass-proof deny-all egress for untrusted install hooks.
  Backends: `unshare` (root or rootless user namespace) or `bubblewrap`. Refuses
  rather than running unprotected when the host can't isolate.

## [0.5.0] — Web UI

- **`afw serve`**: a zero-dependency local web app. Drag-drop a skill folder or
  `.zip` and read the verdict, trust tier and findings in a browser. Loopback-only
  by default, token-protected JSON API, path-traversal-safe uploads.
- Developer docs: `docs/ARCHITECTURE.md` and `docs/USAGE.md`.

## [0.4.0] — Runtime firewall

- **`afw run`**: default-deny egress firewall (filtering proxy) around a command;
  `--fail-on-egress` for CI.
- **`afw mcp-proxy`**: inspect/redact/block an MCP server's JSON-RPC tool calls and
  results in real time (tool poisoning, secret egress, injected instructions).

## [0.3.0] — Provenance & trust zoning

- Trust tiers (`UNTRUSTED` → `DECLARED` → `PINNED` → `VERIFIED`) from signature /
  attestation / SBOM detection; untrusted artifacts held to a stricter policy.
- Threat-intel / IoC feeds (`AFW-IOC-*`): match name, file hash, domain and signer
  against pluggable, offline-by-default feeds.

## [0.2.0] — Framework mapping & rug-pull defense

- Every detection mapped to OWASP LLM / OWASP Agentic / MITRE ATLAS / MCP / SLSA;
  `afw rules` reports framework coverage.
- New static detections: embedded secrets, unsafe deserialization, improper output
  handling, tool poisoning, memory poisoning, anti-forensics, typosquatting.
- **`afw pin`** + `--baseline`: stateful rug-pull detection (`AFW-DRIFT-*`).

## [0.1.0] — Initial release

- Static scanner for AI agents, skills, MCP servers and plugins (dir/file/zip).
- Detections for secret access, exfiltration, obfuscation, destructive actions,
  prompt injection, hidden unicode, permission overreach, install hooks.
- `scan` / `verify` / `install` / `watch` / `rules`; ALLOW/WARN/BLOCK policy;
  text / JSON / SARIF output. MIT licensed, zero required dependencies.

[Unreleased]: https://github.com/mmedabo/agentfirewall/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/mmedabo/agentfirewall/releases/tag/v1.3.1
[1.3.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v1.3.0
[1.2.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v1.2.0
[1.1.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v1.1.0
[1.0.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v1.0.0
[0.9.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.9.0
[0.8.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.8.0
[0.7.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.7.0
[0.6.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.6.0
[0.5.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.5.0
[0.4.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.4.0
[0.3.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.3.0
[0.2.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.2.0
[0.1.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.1.0
