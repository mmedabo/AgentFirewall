# AgentFirewall Threat Model

This document explains **what AgentFirewall defends against, how it thinks about
the problem as a firewall, and how each detection maps to an industry security
framework.** It is the reference that ties our rules to recognised taxonomies so
security reviewers can reason about coverage instead of trusting a black box.

## 1. What we are protecting

The asset is **the machine (and the agent) of a person who installs a third-party
AI artifact** — a skill, an agent definition, an MCP server, or a plugin. These
artifacts are distributed like npm packages or browser extensions: a bundle of
markdown, manifests, and scripts authored by someone you do not know. Installing
one grants it a foothold in a trusted context (your shell, your files, your
agent's tool permissions, your model's context window).

## 2. Adversary & attack surface

| Adversary | Goal | Typical vector |
|---|---|---|
| Malicious author | Steal secrets, persist, exfiltrate | Poisoned `setup.sh`, hidden instructions in `SKILL.md` |
| Compromised maintainer / insider | Ship clean, then mutate | **Rug pull** update, insider BCC (Postmark, 2025) |
| Supply-chain attacker | Trick you into the wrong package | Typosquat / homoglyph name, dependency confusion |
| Prompt-injection author | Steer the model, not the OS | Directives in tool descriptions (**tool poisoning**), invisible unicode |

The attack surface of an artifact is therefore **four boundaries**: its *code/scripts*
(hit the OS), its *manifests/permissions* (hit the agent's authority), its
*model-facing text* (hit the model's context), and its *evolution over time* (hit
you after you already trusted it).

## 3. Trust model & assumptions

- AgentFirewall performs **static analysis** plus **stateful diffing**. It reads
  artifacts; it never executes them. It is therefore safe to point at untrusted
  content.
- A clean verdict means *"nothing matched our detections and nothing drifted from
  the approved baseline"* — **not** a proof of safety. `HIGH`/`CRITICAL` findings
  must be reviewed by a human.
- Detection is signature- and heuristic-based, so it can be evaded by a
  sufficiently novel payload. This is why we add the **stateful** and (planned)
  **runtime** layers: defence in depth, not a single oracle.
- We assume the person running AgentFirewall controls the policy and the baseline
  (`afw.lock`) and stores the baseline somewhere the artifact cannot rewrite.

## 4. The firewall model

A network firewall is a *stack* of mechanisms, not one thing. AgentFirewall is
built to mirror that stack for AI artifacts:

| Firewall mechanism | Network meaning | AgentFirewall analog | Status |
|---|---|---|---|
| Packet filtering (stateless) | Match each packet vs static rules | **Signature rules** — match each line vs a pattern | ✅ shipped |
| Stateful inspection | Track connection state across time | **Baseline + diff** (`afw pin` / `--baseline`) — remember approved shape, flag drift | ✅ shipped |
| Default-deny | Deny all, allow known-good | `--strict` policy + planned `--default-deny` capability allowlist | ⚠️ partial |
| Trust zones / segmentation | Different bar per zone | **Trust tiers** from provenance (`afw pin`, signatures, SBOM) tighten policy | ✅ shipped |
| Egress filtering | Control outbound to stop exfiltration | **`afw run`** — default-deny filtering proxy on the agent's outbound traffic | ✅ shipped |
| Network jail (bypass-proof) | Physically cut off the network | **`afw run --isolate`** — kernel network namespace, no external route | ✅ shipped |
| Egress allowlist (bypass-proof) | Reach these hosts, nothing else, kernel-enforced | **`afw run --isolate --allow`** — netns + Unix-socket filtering broker | ✅ shipped |
| WAF / reverse proxy (L7) | Inspect each app-layer request | **`afw mcp-proxy`** — inspect/redact/block each MCP tool call & result | ✅ shipped |
| IDS vs IPS | Detect vs prevent | `scan` (detect) vs `verify`/`install` gate (prevent) | ✅ shipped |
| Threat-intel feeds | Known-bad IoCs | Pluggable malicious name/domain/hash/signer feeds (`AFW-IOC-*`) | ✅ shipped |
| Policy/rulebase | Ordered ruleset | `Policy` (thresholds, ignore, categories, trust tightening) | ✅ shipped |

The three tiers, in defence-in-depth order:

```
PRE-INSTALL (static)     scan the artifact's code, manifests and model-facing text
INSTALL-TIME (stateful)  pin a baseline; re-verify every update  → rug-pull defense
RUNTIME (dynamic)        egress firewall + tool-call proxy        → afw run / afw mcp-proxy
```

## 5. Detection catalogue → framework mapping

Every detection cites the framework(s) it maps to (see `agentfirewall/frameworks.py`);
`afw rules` prints live coverage. Frameworks referenced:

- **OWASP Top 10 for LLM Applications (2025)** — LLM01…LLM10
- **OWASP Top 10 for Agentic Applications (2026)**
- **MITRE ATLAS** — adversary tactics/techniques for AI systems
- **MCP threat research** — tool poisoning, rug pulls (Invariant Labs; MCP-38)
- **Supply-chain integrity** — SLSA / Sigstore; typosquatting & dependency confusion

| Rule | Severity | Category | Framework references |
|---|---|---|---|
| `AFW-SEC-001…006` | up to CRITICAL | secret-access | OWASP-LLM02, MITRE-ATLAS:Credential-Access |
| `AFW-NET-001…006` | up to CRITICAL | exfiltration | MITRE-ATLAS:Exfiltration, OWASP-LLM02 |
| `AFW-OBF-001…005` | up to CRITICAL | obfuscation | MITRE-ATLAS:Execution, Defense-Evasion |
| `AFW-DES-001…005` | up to CRITICAL | destructive | MITRE-ATLAS:Impact, OWASP-LLM06 |
| `AFW-FS-001…003` | up to HIGH | filesystem | MITRE-ATLAS:Credential-Access, OWASP-LLM02 |
| `AFW-KEY-001…006` | up to HIGH | embedded-secret | OWASP-LLM02 |
| `AFW-DSR-001…003` | up to HIGH | deserialization | OWASP-LLM04, MITRE-ATLAS:Execution |
| `AFW-OUT-001…002` | up to HIGH | output-handling | OWASP-LLM05 |
| `AFW-AF-001…002` | up to HIGH | anti-forensics | OWASP-Agentic:Repudiation, MITRE-ATLAS:Defense-Evasion |
| `AFW-MEM-001…002` | HIGH | memory-poisoning | OWASP-Agentic:Memory-Poisoning, OWASP-LLM01 |
| `AFW-INJ-001` | HIGH | prompt-injection | OWASP-LLM01, MITRE-ATLAS:AML.T0051 |
| `AFW-UNI-001…003` | up to CRITICAL | hidden-content | OWASP-LLM01, MCP:Tool-Poisoning |
| `AFW-BLOB-001` | MEDIUM | obfuscation | MITRE-ATLAS:Defense-Evasion, OWASP-LLM02 |
| `AFW-PERM-001…003` | up to HIGH | permissions | OWASP-LLM06, OWASP-Agentic:Privilege-Compromise |
| `AFW-MCP-001…002` | up to HIGH | permissions | OWASP-LLM06, OWASP-Agentic:Privilege-Compromise |
| `AFW-HOOK-001…002` | up to MEDIUM | install-hook | OWASP-LLM03, MITRE-ATLAS:Execution |
| `AFW-TPZ-001…002` | HIGH | tool-poisoning | MCP:Tool-Poisoning, OWASP-LLM01, MITRE-ATLAS:AML.T0053 |
| `AFW-SQT-001…002` | MEDIUM | typosquatting | Supply-Chain:Typosquatting, OWASP-LLM03 |
| `AFW-DRIFT-001…004` | up to HIGH | integrity/rug-pull | MCP:Rug-Pull, SLSA:Provenance |
| `AFW-DRIFT-010…013` | up to CRITICAL | rug-pull | MCP:Rug-Pull, OWASP-Agentic:Privilege-Compromise |
| `AFW-PROV-001…002` | INFO | provenance | SLSA:Unsigned-Artifact, SLSA:Provenance |
| `AFW-IOC-001…004` | up to CRITICAL | threat-intel | Threat-Intel:Known-Malicious-IoC, Revoked-Signer |

## 6. The rug-pull defense (stateful layer)

Static scanning cannot catch an attack whose malicious payload **arrives later**.
The dangerous MCP incidents of 2025 — rug pulls and the Postmark insider update —
shipped a clean version first, then mutated after the user granted trust.

AgentFirewall answers this with a **baseline**:

1. `afw pin <artifact>` records `afw.lock`: a SHA-256 of every file plus a
   normalized snapshot of the declared *surface* (tools, permissions, MCP servers,
   tool descriptions).
2. `afw verify <artifact> --baseline afw.lock` diffs the current artifact against
   the baseline on every update. A previously-clean tool whose **description or
   permission set silently changed is itself the alarm** (`AFW-DRIFT-01x`,
   escalating a new tool grant to `CRITICAL`), even when the new code contains no
   known-bad signature.

Store the lock file where the artifact cannot rewrite it, and re-pin only after a
human reviews the diff.

## 7. Trust zoning & threat intel (provenance layer)

A firewall does not treat every source the same. AgentFirewall assigns each
artifact a **trust tier** from the independent provenance it can find:

| Tier | Meaning |
|---|---|
| `UNTRUSTED` | No signature, attestation, SBOM, or local baseline. |
| `DECLARED` | Signature / attestation / SBOM files are present but **not** verified. |
| `PINNED` | The user holds a local `afw.lock` baseline for it (a real local anchor). |
| `VERIFIED` | A signature was cryptographically verified (`--verify-signatures`). |

The tier feeds policy: an `UNTRUSTED` artifact is held to a **stricter bar** — the
block threshold tightens by one severity level (so a borderline `MEDIUM` finding on
an unsigned, unpinned artifact blocks). `afw pin` raises trust to `PINNED`;
`--no-tighten-untrusted` opts out. This is deliberately honest: *presence* of a
signature file is not *proof*, so an unverified signature only reaches `DECLARED`.

**Threat intel** answers a different question — is this artifact *known* bad? —
matching its name, file hashes, contacted domains, and signer identity against
pluggable, offline-by-default IoC feeds (`AFW-IOC-*`). This is the firewall analog
of an IP/domain blocklist.

## 8. Runtime firewall (dynamic layer)

Static analysis inspects an artifact at rest; the runtime layer watches it *while
it runs*, which is where exfiltration and injected-instruction attacks actually
happen. It is the difference between reading a program and putting a firewall in
front of it.

**Egress firewall — `afw run`.** Runs a command with its outbound HTTP(S) routed
through a **default-deny filtering proxy**. Only allowlisted destinations
(`--allow *.github.com`) are forwarded; everything else gets a `403` and is logged.
This blocks data exfiltration *even for a payload no static rule recognised* —
the destination simply isn't reachable.

```
afw run --allow *.github.com -- npx some-agent    # blocks any egress off github.com
```

**MCP tool-call proxy — `afw mcp-proxy`.** Sits between the agent and an MCP server
over stdio, like a WAF in front of a web app, and inspects every JSON-RPC message:

| Direction | Message | What we look for |
|---|---|---|
| server → client | `tools/list` result | tool poisoning in descriptions |
| client → server | `tools/call` params | secret egress, injected content in arguments |
| server → client | tool result | injected instructions, secrets flowing into context (DLP) |

On a severe finding it **forwards**, **redacts** the offending text, or **blocks**
the message (answering a blocked call with a JSON-RPC error), per `--action`.

**Bypass-proof isolation — `afw run --isolate`.** For the case where proxy-level
egress isn't enough — running an untrusted install hook or setup script — this
runs the command in a **kernel network namespace with no external interface**. The
process physically cannot reach any host, even with raw sockets, even as root
inside the namespace. It's default-deny egress enforced by the kernel, not by the
client's cooperation. Loopback is available inside the jail; if the host can't
create a namespace, `--isolate` refuses rather than running unprotected.

```
afw run --isolate -- bash setup.sh    # zero network, kernel-enforced
```

**Bypass-proof allowlisting — `afw run --isolate --allow <host>`.** The strongest
mode: reach these hosts and *nothing else*, and a process can't escape it. The
command runs in a namespace with no IP connectivity; its egress is brokered
through a **Unix-domain-socket filtering proxy** in the parent. A UDS crosses the
namespace boundary because it's filesystem-based, not IP-based — so the broker (in
the parent, with real network) enforces the allowlist, while a process that ignores
the proxy and opens a raw socket simply gets no network. Pure `unshare` + stdlib,
no external dependencies.

```
afw run --isolate --allow "*.github.com" -- npx some-agent   # only github.com, escape-proof
```

**Enforcement scope — stated honestly.** Three tools, increasing strength:
*`--allow` (proxy)* filters to an allowlist but governs only clients that honour
`HTTP(S)_PROXY`; *`--isolate` (namespace)* is bypass-proof but all-or-nothing;
*`--isolate --allow` (namespace + broker)* is bypass-proof **and** allowlisted. The
broker sees only connection destinations (for HTTPS it allowlists the CONNECT host
but can't read the encrypted body — same as any egress firewall); the MCP proxy
handles app-layer inspection. Deeper syscall/filesystem confinement (seccomp /
Landlock beyond bubblewrap) remains Phase 5.x.

## 9. Known limitations

- Static rules can be evaded by novel obfuscation; entropy/unicode heuristics
  reduce but do not eliminate this.
- We do not yet execute artifacts in a sandbox, so runtime-only behaviour
  (dynamically fetched payloads) is caught only by its static tells today — the
  planned runtime layer closes this.
- Typosquat detection uses a seed list of popular names; it is best-effort.

See [ROADMAP.md](ROADMAP.md) for how the remaining firewall layers are planned.
