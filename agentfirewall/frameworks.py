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
LLM10_UNBOUNDED = "OWASP-LLM10:Unbounded-Consumption"

# --- OWASP Top 10 for Agentic Applications (2026) --------------------------- #
AGENTIC_MEMORY_POISONING = "OWASP-Agentic:Memory-Poisoning"
AGENTIC_TOOL_MISUSE = "OWASP-Agentic:Tool-Misuse"
AGENTIC_PRIVILEGE_COMPROMISE = "OWASP-Agentic:Privilege-Compromise"
AGENTIC_INTENT_MANIPULATION = "OWASP-Agentic:Intent-Breaking-and-Goal-Manipulation"
AGENTIC_REPUDIATION = "OWASP-Agentic:Repudiation-and-Untraceability"
AGENTIC_IDENTITY_SPOOFING = "OWASP-Agentic:Identity-Spoofing-and-Impersonation"

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

# --- Supply-chain integrity ------------------------------------------------- #
SLSA_PROVENANCE = "SLSA:Provenance-and-Integrity"
SUPPLY_TYPOSQUATTING = "Supply-Chain:Typosquatting"
