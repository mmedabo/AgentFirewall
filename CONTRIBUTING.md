# Contributing to AgentFirewall

Thanks for helping make AI agents safer to install! Contributions of new
detections, better heuristics, docs, and bug fixes are all welcome.

## Getting set up

```bash
git clone https://github.com/mmedabo/AIAgentFirewall
cd agentfirewall
pip install -e ".[dev]"
pytest
```

## Adding a detection

Most detections are a single regex signature. Add one to the relevant
`PatternRule` in `agentfirewall/rules/signatures.py`:

```python
compile_sig(
    "AFW-NET-007",                       # unique id: AFW-<CATEGORY>-<NNN>
    "Contacts known-bad host",           # short title
    Severity.HIGH,                       # INFO | LOW | MEDIUM | HIGH | CRITICAL
    r"bad-host\.example",                # regex (IGNORECASE by default)
    "Reaches a host used for exfiltration.",  # message shown to the user
    "Remove this network call.",         # remediation advice
    # requires_also=r"secret|token",     # optional: only fire with extra context
)
```

For logic that a regex can't express (structure, entropy, cross-file reasoning),
subclass `Rule` in `agentfirewall/rules/structural.py`, implement `check`, and add
your instance to `STRUCTURAL_RULES`.

### Guidelines

- **Prefer precision.** A noisy rule that cries wolf gets ignored. Use severity
  honestly and add `requires_also` context gates when a pattern is only dangerous
  in combination (e.g. an outbound POST *plus* reading secrets).
- **Every new rule needs a test** in `tests/`. Add a positive case (it fires) and,
  ideally, a negative case (it doesn't fire on benign input).
- **Keep it dependency-free.** The core must run with only the standard library.
- **Explain the risk.** The `message` should tell a non-expert *why* it matters.

## Severity guide

| Severity | Meaning |
|---|---|
| CRITICAL | Near-certain compromise (reverse shell, credential theft + egress, `curl \| bash`). |
| HIGH | Strong signal of malicious or dangerous intent (exfiltration, prompt injection, persistence). |
| MEDIUM | Suspicious and worth review (raw-IP egress, encoded blobs, unrestricted shell perms). |
| LOW | Minor / informational risk (a powerful tool is requested legitimately). |
| INFO | Noteworthy but not a risk on its own. |

## Tests & style

- Run `pytest` before opening a PR; keep it green.
- Match the existing code style (type hints, small focused functions, docstrings).

## Reporting security issues

If you find a way to make a malicious artifact slip past the firewall, please open
an issue describing the bypass so we can add a detection.
