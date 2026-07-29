# Changelog

All notable changes to AgentFirewall are documented here. This project follows
[Semantic Versioning](https://semver.org/) and
[Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

- Packaging: reusable GitHub Action (`action.yml`) and a tag-triggered release
  workflow that publishes to PyPI via Trusted Publishing.

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

[Unreleased]: https://github.com/mmedabo/agentfirewall/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.6.0
[0.5.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.5.0
[0.4.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.4.0
[0.3.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.3.0
[0.2.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.2.0
[0.1.0]: https://github.com/mmedabo/agentfirewall/releases/tag/v0.1.0
