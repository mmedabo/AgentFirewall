# Security Policy

## What AgentFirewall is

AgentFirewall is a **defensive** static-analysis tool. It reads AI agent
artifacts (skills, agents, MCP servers, plugins) and reports suspicious
behaviour. It never executes the artifacts it scans, so it is safe to point at
untrusted content.

Like any scanner, it is a strong first line of defence — not a guarantee. A clean
verdict means "nothing matched our detections," not "definitely safe." Always
review `HIGH`/`CRITICAL` findings, and read the code yourself before trusting an
agent with anything sensitive.

## Reporting a bypass or vulnerability

If you find a way to make a genuinely malicious artifact receive an **ALLOW** or
**WARN** verdict when it should be blocked, please report it:

- Open a GitHub issue describing the bypass and, ideally, a minimal example
  artifact that reproduces it.
- For issues you'd rather not disclose publicly, use GitHub's
  [private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
  on this repository.

We treat detection bypasses as bugs and aim to add a signature or rule for each
one.

## Supported versions

This project is pre-1.0; fixes land on `main`. Pin a released version for
reproducible CI.
