"""Canonical identifiers for the security frameworks AgentFirewall maps onto.

Every detection cites one or more of these so a finding can be traced back to a
recognised industry taxonomy (OWASP, MITRE ATLAS, MCP threat research, SLSA).
This is what lets ``afw rules`` report *framework coverage* rather than just a
pile of ad-hoc checks.

References:
  * OWASP Top 10 for LLM Applications (2025) -- https://genai.owasp.org/llm-top-10/
  * OWASP Top 10 for Agentic Applications (2026) -- https://genai.owasp.org/
  * MITRE ATLAS -- https://atlas.mitre.org/
  * MCP threat research (Invariant Labs, MCP-38 taxonomy)
  * SLSA / Sigstore supply-chain integrity -- https://slsa.dev/
"""
from __future__ import annotations

# --- OWASP Top 10 for LLM Applications (2025) ------------------------------- #
LLM01_PROMPT_INJECTION = "OWASP-LLM01:Prompt-Injection"
LLM02_SENSITIVE_INFO = "OWASP-LLM02:Sensitive-Information-Disclosure"
LLM03_SUPPLY_CHAIN = "OWASP-LLM03:Supply-Chain"
LLM04_DATA_POISONING = "OWASP-LLM04:Data-and-Model-Poisoning"
LLM05_OUTPUT_HANDLING = "OWASP-LLM05:Improper-Output-Handling"
LLM06_EXCESSIVE_AGENCY = "OWASP-LLM06:Excessive-Agency"
LLM07_SYSTEM_PROMPT_LEAK = "OWASP-LLM07:System-Prompt-Leakage"
LLM08_VECTOR_EMBEDDING = "OWASP-LLM08:Vector-and-Embedding-Weaknesses"
LLM10_UNBOUNDED = "OWASP-LLM10:Unbounded-Consumption"

# --- OWASP Top 10 for Agentic Applications 2026 (ASI01-ASI10) ---------------- #
# Official identifiers from the OWASP GenAI Security Project (published 2025-12-09).
AGENTIC_GOAL_HIJACK = "OWASP-ASI01:Agent-Goal-Hijack"
AGENTIC_TOOL_MISUSE = "OWASP-ASI02:Tool-Misuse-and-Exploitation"
AGENTIC_PRIVILEGE_COMPROMISE = "OWASP-ASI03:Identity-and-Privilege-Abuse"
AGENTIC_SUPPLY_CHAIN = "OWASP-ASI04:Agentic-Supply-Chain"
AGENTIC_RCE = "OWASP-ASI05:Unexpected-Code-Execution"
AGENTIC_MEMORY_POISONING = "OWASP-ASI06:Memory-and-Context-Poisoning"
AGENTIC_INTER_AGENT = "OWASP-ASI07:Insecure-Inter-Agent-Communication"
AGENTIC_CASCADING = "OWASP-ASI08:Cascading-Failures"
AGENTIC_HUMAN_TRUST = "OWASP-ASI09:Human-Agent-Trust-Exploitation"
AGENTIC_ROGUE = "OWASP-ASI10:Rogue-Agents"

# Back-compat aliases for concepts named before the 2026 Top 10 finalized IDs.
AGENTIC_INTENT_MANIPULATION = AGENTIC_GOAL_HIJACK          # -> ASI01
AGENTIC_IDENTITY_SPOOFING = AGENTIC_PRIVILEGE_COMPROMISE   # -> ASI03
# Repudiation/untraceability is from the OWASP Agentic Threats & Mitigations guide
# (not a numbered ASI risk); keep an explicit reference for anti-forensics findings.
AGENTIC_REPUDIATION = "OWASP-Agentic:Repudiation-and-Untraceability"

# --- MITRE ATLAS techniques ------------------------------------------------- #
ATLAS_EXFILTRATION = "MITRE-ATLAS:Exfiltration"
ATLAS_LLM_PLUGIN_COMPROMISE = "MITRE-ATLAS:AML.T0053:LLM-Plugin-Compromise"
ATLAS_LLM_PROMPT_INJECTION = "MITRE-ATLAS:AML.T0051:LLM-Prompt-Injection"
ATLAS_UNSECURED_CREDENTIALS = "MITRE-ATLAS:Credential-Access"
ATLAS_PERSISTENCE = "MITRE-ATLAS:Persistence"
ATLAS_DEFENSE_EVASION = "MITRE-ATLAS:Defense-Evasion"
ATLAS_EXECUTION = "MITRE-ATLAS:Execution"
ATLAS_IMPACT = "MITRE-ATLAS:Impact"

# --- MCP-specific threat classes -------------------------------------------- #
MCP_TOOL_POISONING = "MCP:Tool-Poisoning"
MCP_RUG_PULL = "MCP:Rug-Pull"
MCP_TOOL_SHADOWING = "MCP:Tool-Shadowing"

# --- Deployed-agent application abuse (guardrails / business logic) ---------- #
API_BROKEN_AUTHZ = "OWASP-API:Broken-Function-Level-Authorization"
API_RESOURCE = "OWASP-API:Unrestricted-Resource-Consumption"
CWE_TOCTOU = "CWE-367:TOCTOU-Race-Condition"
CWE_CLIENT_ENFORCE = "CWE-602:Client-Side-Enforcement-of-Server-Side-Security"

# --- Supply-chain integrity ------------------------------------------------- #
SLSA_PROVENANCE = "SLSA:Provenance-and-Integrity"
SLSA_UNSIGNED = "SLSA:Unsigned-Artifact"
SUPPLY_TYPOSQUATTING = "Supply-Chain:Typosquatting"
SUPPLY_SLOPSQUATTING = "Supply-Chain:Slopsquatting"
SUPPLY_KNOWN_MALICIOUS = "Threat-Intel:Known-Malicious-IoC"
SUPPLY_REVOKED_SIGNER = "Threat-Intel:Revoked-Signer"
