# Changelog

All notable changes to AgentFirewall are documented here. This project follows
[Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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

[Unreleased]: https://github.com/mmedabo/agentfirewall/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.9.0
[0.8.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.8.0
[0.7.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.7.0
[0.6.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.6.0
[0.5.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.5.0
[0.4.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.4.0
[0.3.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.3.0
[0.2.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.2.0
[0.1.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.1.0
