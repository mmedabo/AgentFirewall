# AgentFirewall Architecture

This is the developer's-eye view: how the pieces fit, how data flows through them,
and where to plug in new behaviour. For *what* it defends against and *why*, see
[THREAT-MODEL.md](THREAT-MODEL.md); for *how to use it*, see [USAGE.md](USAGE.md).

## Design principles

1. **Engine / interface separation.** All security logic lives in importable
   modules with no CLI or web coupling. The CLI, the web UI, and your own Python
   code are just three consumers of the same `Scanner`.
2. **Zero required dependencies.** The core runs on the standard library alone, so
   the tool you use to *check* untrusted things doesn't drag in a supply chain of
   its own. (`PyYAML` is an optional nicety; the web UI and runtime layer are pure
   stdlib.)
3. **Static by default, honest about limits.** The scanning tiers read artifacts,
   never execute them. The runtime tier is clearly scoped (proxy-level egress).
4. **Everything maps to a framework.** Each detection cites OWASP/ATLAS/MCP/SLSA
   identifiers so coverage is auditable, not vibes.

## Module map

```
agentfirewall/
  models.py        Severity, Verdict, TrustTier, Finding, ScannedFile, Artifact, ScanResult
  frameworks.py    Canonical OWASP / ATLAS / MCP / SLSA reference identifiers
  loaders.py       path (dir/file/zip) → Artifact (+ manifest parsing, per-file sha256)
  policy.py        Policy: findings + trust tier → ALLOW/WARN/BLOCK verdict
  scanner.py       Scanner: orchestrates rules + baseline diff + provenance + intel
  baseline.py      pin/diff (afw.lock) — the rug-pull defense
  provenance.py    signature/attestation/SBOM detection → TrustTier
  intel.py         threat-intel / IoC feeds (names, hashes, domains, signers)
  report.py        render ScanResult as text / JSON / SARIF
  cli.py           argparse front-end (scan, verify, install, pin, run, mcp-proxy, serve, …)
  rules/
    base.py        Rule, Signature, PatternRule (regex engine)
    signatures.py  the signature library (PatternRules by category)
    structural.py  heuristic rules (injection, unicode, entropy, permissions, tool poisoning…)
    __init__.py    all_rules() registry
  runtime/
    egress.py      EgressPolicy + EgressProxy (default-deny filtering proxy)
    sandbox.py     run_guarded() — a command behind the egress firewall (afw run)
    mcp_proxy.py   McpInspector + stdio relay (afw mcp-proxy)
    isolation.py   run_isolated() / run_allowlisted() — kernel netns jail (afw run --isolate)
    _jailrun.py    in-namespace supervisor: loopback + TCP→UDS forwarder for allowlisting
  web/
    server.py      stdlib HTTP server + token-guarded JSON API (afw serve)
    index.html     self-contained SPA
  data/intel/      bundled seed IoC feed
```

## The vocabulary (`models.py`)

Everything speaks in these types:

- **`Severity`** — `INFO < LOW < MEDIUM < HIGH < CRITICAL` (an `IntEnum`, so it
  sorts and thresholds).
- **`Finding`** — one issue: `rule_id`, `severity`, `category`, `message`,
  `path`/`line`, `evidence`, `remediation`, and `references` (framework tags).
- **`ScannedFile`** — one file: `path`, `text`, `is_binary`, `role`
  (`manifest`/`script`/`doc`/`config`), `sha256`.
- **`Artifact`** — the thing scanned: `name`, `kind`, `files`, and `metadata`
  (declared tools/permissions, MCP servers, tool descriptions, MCP risks).
- **`Verdict`** — `ALLOW` / `WARN` / `BLOCK` (carries an `exit_code`).
- **`TrustTier`** — `UNTRUSTED < DECLARED < PINNED < VERIFIED`.
- **`ScanResult`** — the full outcome: artifact, findings, verdict, trust tier,
  provenance summary. `to_dict()` is the stable JSON contract the CLI and web UI
  both serialize.

## Data flow

```
                         ┌─────────────── Scanner.scan_artifact ───────────────┐
 path ──▶ loaders.load ──▶ rules (all_rules)      ─┐                            │
 (dir/file/zip)  │         baseline.diff(lock)     ├─▶ findings ─▶ policy ──────▶ ScanResult
                 │         provenance.detect ───────┤     (filter,   .decide(     │  (verdict,
                 ▼         intel.check ─────────────┘      dedupe,   trust_tier)  │   trust tier,
            Artifact                                        sort)                 │   provenance)
            (files + metadata)                                                    │
                         └────────────────────────────────────────────────────────┘
```

1. **Load.** `loaders.load()` walks a directory / reads a file / unzips an archive
   into an `Artifact`. It recognises skills (`SKILL.md`), agents, MCP configs and
   plugins, parses YAML frontmatter (dependency-free) to pull declared
   tools/permissions, extracts MCP `env` secrets, auto-approve flags and tool
   descriptions, and hashes every file (`sha256`) for baselining.
2. **Detect.** `Scanner` runs every rule from `all_rules()`. Each `Rule.check()`
   yields `Finding`s. A broken rule is caught and turned into an `INFO` finding
   rather than aborting the scan.
3. **Cross-cutting analyses.** If a baseline was supplied, `baseline.diff()` adds
   drift findings. `provenance.detect()` computes the trust tier and adds
   provenance findings. If threat intel is configured, `intel.check()` adds IoC
   findings.
4. **Decide.** `policy.filter()` drops suppressed findings; the scanner dedupes and
   sorts by severity; `policy.decide(findings, trust_tier)` returns the verdict —
   tightening the block threshold for `UNTRUSTED` artifacts.
5. **Render.** `report.py` turns the `ScanResult` into text / JSON / SARIF; the web
   UI consumes the same `to_dict()`.

## The rule engine (`rules/`)

Two kinds of rule, both subclasses of `Rule` (`rules/base.py`):

- **`PatternRule`** — a family of regex `Signature`s scanned line-by-line. Most
  detections are just data: `compile_sig(id, title, severity, pattern, message,
  remediation, requires_also=…, references=…)`. A `requires_also` regex is a
  context gate (fire only if a second pattern is also present in the file). A rule
  can set `default_references` so a whole category shares a framework mapping.
- **Structural rules** — arbitrary Python for things a single regex can't express:
  prompt injection, invisible-unicode/entropy analysis, permission overreach, tool
  poisoning (reads structured tool descriptions), typosquatting (edit distance +
  homoglyphs).

`all_rules()` in `rules/__init__.py` is the registry the scanner runs.

Some detections live **outside** the registry because they need extra inputs and
run in the scanner directly: `AFW-DRIFT-*` (baseline diff), `AFW-PROV-*`
(provenance), `AFW-IOC-*` (threat intel). `afw rules` lists these too.

## The runtime layer (`runtime/`)

Independent of the scanning pipeline — it watches execution rather than files:

- **`EgressProxy`** is a threaded filtering forward proxy. `run_guarded()` sets
  `HTTP(S)_PROXY` for a child process and records every `CONNECT`/HTTP attempt,
  forwarding allowlisted destinations and returning `403` for the rest.
- **`McpInspector`** applies a subset of the rule engine to JSON-RPC messages and
  returns a `Decision` (`forward` / `redact` / `block`). `run_stdio_proxy()` relays
  newline-delimited JSON-RPC between an agent and a spawned MCP server, enforcing
  those decisions.
- **`isolation.run_isolated()`** runs a command in a kernel network namespace with
  no external interface (bypass-proof deny-all egress), via `unshare` or
  `bubblewrap`. `probe()` reports what the host supports; the runner refuses rather
  than silently running unprotected.
- **`isolation.run_allowlisted()`** is bypass-proof *allowlisting*: it starts an
  `EgressProxy` on a **Unix socket** in the parent, then launches the command in a
  no-IP namespace running `_jailrun` (which brings up loopback, runs a TCP→UDS
  forwarder, and points `HTTP(S)_PROXY` at it). The UDS reaches across the namespace
  boundary — IP traffic can't — so the broker's allowlist is the only egress.

## Extension points

| To add… | Do this |
|---|---|
| A signature detection | Append a `compile_sig(...)` to the right `PatternRule` in `rules/signatures.py`. |
| A structural detection | Subclass `Rule` in `rules/structural.py`, add it to `STRUCTURAL_RULES`. |
| A new artifact type | Teach `loaders._classify()` / `_role_for()` to recognise it and populate `metadata`. |
| A framework mapping | Add a constant to `frameworks.py`, reference it from the rule. |
| A threat-intel source | Point `--intel` at a JSON/txt feed, or extend `ThreatIntel._load_file`. |
| An output format | Add a `render_*` in `report.py` and wire a `--format` choice in `cli.py`. |
| A trust signal | Extend `provenance.detect()` / the `TrustTier` ladder. |

Every new detection should ship with a test (positive + ideally negative) — see
[CONTRIBUTING.md](../CONTRIBUTING.md).

## Testing

`pytest` covers each layer: `test_scanner.py`/`test_rules.py` (engine),
`test_phase1.py` (framework detections), `test_baseline.py` (rug pull),
`test_phase3.py` (provenance/intel), `test_phase4.py` (runtime egress + MCP),
`test_web.py` (the web API), and `test_cli.py` (exit codes / gating). The examples
under `examples/` double as fixtures and as a live CI self-check.
