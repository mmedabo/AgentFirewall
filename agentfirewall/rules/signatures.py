"""The signature library: regex-based detections grouped by category.

Each :class:`PatternRule` bundles a family of signatures. Keeping them here as
plain data makes the catalogue easy to audit and extend -- add a line, get a new
detection. Categories map to how a malicious agent artifact typically attacks the
host it is installed into.
"""
from __future__ import annotations

from .. import frameworks as F
from ..models import Severity
from .base import PatternRule, compile_sig

S = Severity

# --------------------------------------------------------------------------- #
# 1. Secret & credential access / exfiltration
# --------------------------------------------------------------------------- #
SECRETS = PatternRule(
    id="secrets",
    category="secret-access",
    default_references=(F.LLM02_SENSITIVE_INFO, F.ATLAS_UNSECURED_CREDENTIALS),
    signatures=[
        compile_sig(
            "AFW-SEC-001", "Reads SSH private keys", S.CRITICAL,
            r"(~|\$HOME|/root|/home/[\w.-]+)/\.ssh(/|\b)|id_rsa\b|id_ed25519\b",
            "Accesses SSH private key material, a classic credential-theft target.",
            "Agents should never need to read ~/.ssh. Remove this access.",
        ),
        compile_sig(
            "AFW-SEC-002", "Reads cloud credential files", S.CRITICAL,
            r"\.aws/credentials|\.aws/config|\.config/gcloud|\.azure/|"
            r"\.kube/config|\.docker/config\.json|\.npmrc|\.pypirc",
            "Reads cloud/registry credential files that grant account access.",
            "Remove reads of cloud credential stores.",
        ),
        compile_sig(
            "AFW-SEC-003", "Dumps environment variables", S.HIGH,
            r"\b(printenv|env)\b\s*(\||>|$)|process\.env\b(?!\.[A-Za-z])|"
            r"os\.environ\b(?!\s*\.get\(\s*['\"][A-Z_]+['\"]\s*\)\s*$)",
            "Reads the whole environment, which usually holds API keys and tokens.",
            "Read only the specific variables you need, not the entire environment.",
        ),
        compile_sig(
            "AFW-SEC-004", "Targets provider API keys", S.HIGH,
            r"ANTHROPIC_API_KEY|OPENAI_API_KEY|AWS_SECRET_ACCESS_KEY|"
            r"AWS_ACCESS_KEY_ID|GITHUB_TOKEN|GH_TOKEN|SLACK_TOKEN|HF_TOKEN|"
            r"GOOGLE_API_KEY|STRIPE_SECRET_KEY",
            "References a known secret environment variable by name.",
            "Do not read provider secrets from within an installed agent.",
        ),
        compile_sig(
            "AFW-SEC-005", "Reads dotenv / secret files", S.MEDIUM,
            r"\b(cat|less|head|tail|source|read)\b[^\n]{0,40}\.env\b|"
            r"open\([^)]*['\"][^'\"]*\.env['\"]",
            "Reads .env files that commonly contain application secrets.",
            "Avoid reading .env files from third-party agents.",
        ),
        compile_sig(
            "AFW-SEC-006", "Accesses OS keychain / secret store", S.HIGH,
            r"\bsecurity\s+find-generic-password\b|\bsecret-tool\b|"
            r"\bkeychain\b|\bgnome-keyring\b|\bvault\s+read\b",
            "Interacts with the OS keychain / secret manager.",
            "Remove keychain access from the artifact.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 2. Network exfiltration & suspicious egress
# --------------------------------------------------------------------------- #
NETWORK = PatternRule(
    id="network",
    category="exfiltration",
    default_references=(F.ATLAS_EXFILTRATION, F.LLM02_SENSITIVE_INFO),
    signatures=[
        compile_sig(
            "AFW-NET-001", "Exfiltration to paste/webhook service", S.HIGH,
            r"\b(pastebin\.com|hastebin\.com|paste\.ee|transfer\.sh|"
            r"webhook\.site|requestbin|pipedream\.net|ngrok\.io|ngrok-free\.app|"
            r"burpcollaborator|oastify\.com|interact\.sh|dnslog\.cn|"
            r"discord(app)?\.com/api/webhooks|hooks\.slack\.com)\b",
            "Contacts a service commonly used to receive exfiltrated data.",
            "Remove calls to paste bins, webhooks and out-of-band collaborators.",
        ),
        compile_sig(
            "AFW-NET-002", "Pipes local data to the network", S.HIGH,
            r"\b(curl|wget|nc|ncat|socat)\b[^\n|]{0,200}(-d|--data|-T|--upload-file|"
            r"-F|--form)\b",
            "Uploads local data to a remote host via curl/wget/netcat.",
            "Verify the destination and that no secrets are being uploaded.",
            requires_also=r"env|printenv|\.ssh|\.aws|\.env|token|password|secret|"
            r"cat\s|read\s|\$\(",
        ),
        compile_sig(
            "AFW-NET-003", "Raw IP address egress", S.MEDIUM,
            r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?",
            "Connects to a hard-coded raw IP address instead of a named host.",
            "Hard-coded IPs in agents are suspicious; confirm the destination.",
        ),
        compile_sig(
            "AFW-NET-004", "Reverse shell pattern", S.CRITICAL,
            r"\bbash\s+-i\b[^\n]{0,40}/dev/tcp/|nc\s+-e\b|ncat\s+-e\b|"
            r"socat\b[^\n]{0,80}EXEC|/dev/tcp/\d",
            "Contains a reverse-shell invocation giving an attacker interactive access.",
            "This is almost never legitimate. Do not install this artifact.",
        ),
        compile_sig(
            "AFW-NET-005", "DNS-based exfiltration", S.HIGH,
            r"\b(nslookup|dig|host)\b[^\n]{0,120}\$\(|"
            r"\.(dnslog|oast|interact|burpcollaborator)\b",
            "Encodes data into DNS lookups, a covert exfiltration channel.",
            "Remove dynamic DNS lookups that embed local data.",
        ),
        compile_sig(
            "AFW-NET-006", "Suspicious outbound POST of data", S.MEDIUM,
            r"requests\.(post|put)\s*\(|fetch\s*\([^)]*method\s*:\s*['\"]POST|"
            r"axios\.(post|put)\s*\(|http\.request\b",
            "Performs an outbound POST/PUT which may carry collected data.",
            "Confirm what is being sent and to where.",
            requires_also=r"env|token|secret|password|os\.environ|process\.env|"
            r"open\(|read\(|\.ssh|\.aws",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 3. Obfuscation & dynamic code execution
# --------------------------------------------------------------------------- #
OBFUSCATION = PatternRule(
    id="obfuscation",
    category="obfuscation",
    default_references=(F.ATLAS_EXECUTION, F.ATLAS_DEFENSE_EVASION),
    signatures=[
        compile_sig(
            "AFW-OBF-001", "Download-and-execute (curl | bash)", S.CRITICAL,
            r"\b(curl|wget)\b[^\n]{0,200}\|\s*(sudo\s+)?(bash|sh|zsh|python[0-9.]*|node|ruby|perl)\b",
            "Pipes a remotely downloaded script straight into a shell/interpreter.",
            "Never pipe untrusted remote content into an interpreter.",
        ),
        compile_sig(
            "AFW-OBF-002", "Dynamic code execution", S.HIGH,
            r"\beval\s*\(|\bexec\s*\(|\bFunction\s*\(\s*['\"]|"
            r"new\s+Function\s*\(|subprocess\.[A-Za-z_]+\([^)]*shell\s*=\s*True",
            "Evaluates code built at runtime, a common way to hide payloads.",
            "Avoid eval/exec on dynamic strings; use explicit calls.",
        ),
        compile_sig(
            "AFW-OBF-003", "Base64 decode-and-run", S.HIGH,
            r"base64\s+(-d|--decode)\b[^\n]{0,80}\|\s*(bash|sh|python|node)|"
            r"b64decode\([^)]*\)[^\n]{0,40}(exec|eval|subprocess|os\.system)|"
            r"atob\s*\([^)]*\)[^\n]{0,40}(eval|Function)",
            "Decodes a Base64 blob and immediately executes it.",
            "Decode-and-execute is a hallmark of hidden malware. Reject it.",
        ),
        compile_sig(
            "AFW-OBF-004", "Hex / escape-encoded payload", S.MEDIUM,
            r"(\\x[0-9a-fA-F]{2}){8,}|(%[0-9a-fA-F]{2}){10,}",
            "Contains a long run of hex/percent-encoded bytes hiding its intent.",
            "Decode and review the payload before trusting it.",
        ),
        compile_sig(
            "AFW-OBF-005", "Shell obfuscation via IFS / variable splicing", S.MEDIUM,
            r"\$\{IFS\}|\$IFS|\bcat<<<|\bprintf\b[^\n]{0,40}\\x",
            "Uses shell tricks (IFS, here-strings) that are typically used to evade filters.",
            "Review obfuscated shell constructs carefully.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 4. Destructive / high-impact system actions
# --------------------------------------------------------------------------- #
DESTRUCTIVE = PatternRule(
    id="destructive",
    category="destructive",
    default_references=(F.ATLAS_IMPACT, F.LLM06_EXCESSIVE_AGENCY),
    signatures=[
        compile_sig(
            "AFW-DES-001", "Recursive force delete of a broad path", S.CRITICAL,
            r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\b[^\n]{0,40}"
            r"(/|~|\$HOME|\*|\.)\s*($|;|&|\|)",
            "Recursively force-deletes a broad path, risking data loss.",
            "Scope deletes narrowly; never rm -rf / or $HOME.",
        ),
        compile_sig(
            "AFW-DES-002", "Disk / filesystem destruction", S.CRITICAL,
            r"\bmkfs\b|\bdd\s+if=[^\n]{0,40}of=/dev/|\b:\(\)\s*\{\s*:\|:&\s*\}",
            "Overwrites disks or contains a fork bomb.",
            "These commands destroy systems. Do not install.",
        ),
        compile_sig(
            "AFW-DES-003", "Weakens system security posture", S.HIGH,
            r"\bchmod\s+(-R\s+)?0?777\b|\bsetenforce\s+0\b|\bufw\s+disable\b|"
            r"\bsystemctl\s+stop\s+(firewalld|ufw)|iptables\s+-F\b|"
            r"export\s+PYTHONHTTPSVERIFY\s*=\s*0|verify\s*=\s*False",
            "Disables firewalls, TLS verification or loosens permissions dangerously.",
            "Do not weaken host security controls from an installed agent.",
        ),
        compile_sig(
            "AFW-DES-004", "Crypto-miner / resource abuse", S.HIGH,
            r"\b(xmrig|minerd|cpuminer|stratum\+tcp|nicehash|coinhive)\b",
            "References cryptocurrency mining software.",
            "This artifact attempts to abuse host resources for mining.",
        ),
        compile_sig(
            "AFW-DES-005", "Persistence via cron / autostart", S.HIGH,
            r"\bcrontab\s+-|/etc/cron|>>?\s*~?/?\.(bashrc|zshrc|profile|bash_profile)|"
            r"launchctl\s+load|systemctl\s+enable\b|/etc/rc\.local|"
            r"\.config/autostart",
            "Installs persistence so it keeps running after the task ends.",
            "Agents should not establish persistence on the host.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 5. Sensitive filesystem access
# --------------------------------------------------------------------------- #
FILESYSTEM = PatternRule(
    id="filesystem",
    category="filesystem",
    default_references=(F.ATLAS_UNSECURED_CREDENTIALS, F.LLM02_SENSITIVE_INFO),
    signatures=[
        compile_sig(
            "AFW-FS-001", "Reads browser / app credential stores", S.HIGH,
            r"Login\s+Data|Cookies\.sqlite|key4\.db|logins\.json|"
            r"Local\s+Storage/leveldb|\.mozilla/firefox|Library/Keychains",
            "Reads browser or application credential/cookie databases.",
            "Session and password theft. Remove this access.",
        ),
        compile_sig(
            "AFW-FS-002", "Reads shell / command history", S.MEDIUM,
            r"\.(bash|zsh)_history|\.python_history|\.psql_history|\.node_repl_history",
            "Reads shell history, which often contains secrets typed by the user.",
            "Do not harvest shell history.",
        ),
        compile_sig(
            "AFW-FS-003", "Broad home-directory sweep", S.MEDIUM,
            r"\bfind\s+(~|\$HOME|/home|/root)\b[^\n]{0,120}(-name|-type\s+f)|"
            r"\btar\b[^\n]{0,80}(~|\$HOME|/home)\b",
            "Recursively scans or archives the user's home directory.",
            "Confirm why the whole home directory is being read/archived.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 6. Embedded credentials shipped inside the artifact (OWASP LLM02)
# --------------------------------------------------------------------------- #
EMBEDDED_SECRETS = PatternRule(
    id="embedded-secrets",
    category="embedded-secret",
    default_references=(F.LLM02_SENSITIVE_INFO,),
    signatures=[
        compile_sig(
            "AFW-KEY-001", "Bundled private key", S.HIGH,
            r"-----BEGIN\s+(RSA|EC|OPENSSH|DSA|PGP)?\s*PRIVATE\s+KEY-----",
            "Ships a private key inside the artifact.",
            "Remove the key; distribute secrets out of band, never in an artifact.",
            flags=0,
        ),
        compile_sig(
            "AFW-KEY-002", "AWS access key id", S.HIGH,
            r"\b(AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b",
            "Contains a hard-coded AWS access key id.",
            "Rotate the key and remove it from the artifact.",
            flags=0,
        ),
        compile_sig(
            "AFW-KEY-003", "GitHub / GitLab token", S.HIGH,
            r"\b(gh[pousr]_[A-Za-z0-9]{36,}|glpat-[A-Za-z0-9_-]{20,})\b",
            "Contains a hard-coded GitHub or GitLab access token.",
            "Revoke the token and remove it from the artifact.",
            flags=0,
        ),
        compile_sig(
            "AFW-KEY-004", "AI provider API key", S.HIGH,
            r"\b(sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{30,})\b",
            "Contains a hard-coded OpenAI/Anthropic/Google API key.",
            "Revoke the key and remove it from the artifact.",
            flags=0,
        ),
        compile_sig(
            "AFW-KEY-005", "Slack token", S.HIGH,
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
            "Contains a hard-coded Slack token.",
            "Revoke the token and remove it from the artifact.",
            flags=0,
        ),
        compile_sig(
            "AFW-KEY-006", "Generic secret assignment", S.MEDIUM,
            r"(?i)\b(api[_-]?key|secret|password|passwd|token|access[_-]?key)\b\s*[:=]\s*"
            r"['\"][^'\"]{12,}['\"]",
            "Assigns a long literal to a secret-looking variable.",
            "Load secrets from the environment or a vault, not literals.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 7. Unsafe deserialization / model-weight poisoning (OWASP LLM04)
# --------------------------------------------------------------------------- #
DESERIALIZATION = PatternRule(
    id="deserialization",
    category="deserialization",
    default_references=(F.LLM04_DATA_POISONING, F.ATLAS_EXECUTION),
    signatures=[
        compile_sig(
            "AFW-DSR-001", "Unsafe pickle deserialization", S.HIGH,
            r"\bpickle\.loads?\s*\(|\bcPickle\.loads?\s*\(|"
            r"numpy\.load\s*\([^)]*allow_pickle\s*=\s*True|\byaml\.load\s*\((?![^)]*Loader)",
            "Deserializes untrusted data with pickle/unsafe YAML, enabling code execution.",
            "Use safe loaders (json, yaml.safe_load, weights_only=True).",
        ),
        compile_sig(
            "AFW-DSR-002", "Loads model weights that can execute code", S.MEDIUM,
            r"\btorch\.load\s*\((?![^)]*weights_only\s*=\s*True)|\bjoblib\.load\s*\(|"
            r"keras\.models\.load_model\s*\(",
            "Loads model weights in a format (pickle-backed) that can run code on load.",
            "Prefer safetensors or torch.load(..., weights_only=True) from trusted sources.",
        ),
        compile_sig(
            "AFW-DSR-003", "Bundled pickle / weight file", S.LOW,
            r"\.(pkl|pickle|pt|pth|bin|h5|joblib|gguf|ckpt)(['\"\s]|$)",
            "References a pickle/weight file that may execute code when loaded.",
            "Verify the provenance of bundled model/data files.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 8. Improper output handling: model/LLM output flowing into a sink (LLM05)
# --------------------------------------------------------------------------- #
OUTPUT_HANDLING = PatternRule(
    id="output-handling",
    category="output-handling",
    default_references=(F.LLM05_OUTPUT_HANDLING,),
    signatures=[
        compile_sig(
            "AFW-OUT-001", "Model output flows into a shell/interpreter", S.HIGH,
            r"(?:(os\.system|subprocess\.[A-Za-z_]+|exec|eval)\s*\([^)]{0,80}"
            r"\b(completion|response|message|llm_?out\w*|model_?out\w*|answer|generated|reply)\b)"
            r"|(?:\b(completion|response|llm_?out\w*|model_?out\w*)\b[\w\[\].\"']*\s*"
            r"[^\n]{0,20}(\||into)[^\n]{0,20}(os\.system|subprocess|\bexec\b|\beval\b|bash|sh\b))",
            "Feeds LLM output directly into command/dynamic execution.",
            "Never execute model output; validate and use structured, allow-listed actions.",
        ),
        compile_sig(
            "AFW-OUT-002", "Unsanitized output into SQL / HTML", S.MEDIUM,
            r"(execute|executescript|cursor\.execute)\s*\([^)]*(completion|response|llm|model_?out)",
            "Interpolates model output into a SQL/HTML sink without sanitization.",
            "Parameterize queries and escape output before rendering.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 9. Anti-forensics / repudiation: covering tracks (Agentic T8, ATLAS)
# --------------------------------------------------------------------------- #
ANTI_FORENSICS = PatternRule(
    id="anti-forensics",
    category="anti-forensics",
    default_references=(F.AGENTIC_REPUDIATION, F.ATLAS_DEFENSE_EVASION),
    signatures=[
        compile_sig(
            "AFW-AF-001", "Clears shell history", S.MEDIUM,
            r"\bhistory\s+-c\b|\bunset\s+HISTFILE\b|\bexport\s+HISTFILE=/dev/null|"
            r"\bset\s+\+o\s+history\b|>\s*~?/?\.(bash|zsh)_history",
            "Disables or wipes shell history to cover its tracks.",
            "Agents should never tamper with the user's command history.",
        ),
        compile_sig(
            "AFW-AF-002", "Deletes or tampers with system logs", S.HIGH,
            r"\b(rm|truncate|shred)\b[^\n]{0,60}/var/log|"
            r">\s*/var/log/[\w./]+|\bjournalctl\b[^\n]{0,20}--vacuum|\bauditctl\s+-D\b|"
            r"\bwevtutil\s+cl\b",
            "Deletes or truncates audit/system logs, a hallmark of anti-forensics.",
            "Removing logs destroys the audit trail; do not install.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 10. Memory / context poisoning: writing to files OTHER agents read (Agentic)
# --------------------------------------------------------------------------- #
MEMORY_POISONING = PatternRule(
    id="memory-poisoning",
    category="memory-poisoning",
    default_references=(F.AGENTIC_MEMORY_POISONING, F.LLM01_PROMPT_INJECTION),
    signatures=[
        compile_sig(
            "AFW-MEM-001", "Writes to an agent instruction file", S.HIGH,
            r"(>>?|open\s*\(|write_text|fs\.(append|write)file\w*)\s*[^\n]{0,40}"
            r"(CLAUDE\.md|AGENTS?\.md|\.cursorrules|\.clinerules|\.windsurfrules|"
            r"copilot-instructions\.md|\.github/instructions|GEMINI\.md)",
            "Writes into an agent instruction/rules file that other agents auto-load, "
            "injecting persistent hidden instructions (memory poisoning).",
            "Agents should not modify instruction files that steer other agents.",
        ),
        compile_sig(
            "AFW-MEM-002", "Modifies agent / MCP configuration", S.HIGH,
            r"(>>?|open\s*\(|write_text)\s*[^\n]{0,40}"
            r"(\.mcp\.json|claude_desktop_config\.json|\.claude/settings|"
            r"\.config/[\w-]*(claude|cursor|cline)|\.continue/config)",
            "Writes into agent or MCP configuration, which can silently add servers, "
            "tools or permissions.",
            "Do not let an installed artifact rewrite agent/MCP configuration.",
        ),
    ],
)

# --------------------------------------------------------------------------- #
# 11. Excessive agency in a DEPLOYED agent (OWASP LLM06 / Agentic Tool-Misuse)
#     Protects an agent *application* from giving its users more power or scope
#     than its business purpose needs (e.g. a food-ordering bot that will run
#     arbitrary Python for anyone who asks).
# --------------------------------------------------------------------------- #
AGENT_AGENCY = PatternRule(
    id="agent-agency",
    category="excessive-agency",
    default_references=(F.LLM06_EXCESSIVE_AGENCY, F.AGENTIC_TOOL_MISUSE),
    signatures=[
        compile_sig(
            "AFW-AGENCY-001", "User input drives code execution", S.CRITICAL,
            r"\b(exec|eval)\s*\(\s*[^)]*\b(user_input|user_message|user_msg|message|"
            r"prompt|query|chat|content|body|params|req\.\w+|request\.\w+|args\[)",
            "Executes code built from user/request input — an end user can run arbitrary "
            "code through the agent (excessive agency / RCE).",
            "Never execute user-supplied code. Expose only specific, validated actions.",
        ),
        compile_sig(
            "AFW-AGENCY-002", "Agent exposes a code-execution/shell tool", S.HIGH,
            r"(?i)(\"name\"\s*:\s*\"|name\s*=\s*['\"]|def\s+|@tool\s*\(?\s*['\"]?)"
            r"(run_python|execute_code|python_repl|code_interpreter|eval_code|run_code|"
            r"exec_shell|shell_exec|run_shell|run_command|arbitrary_code)\b",
            "Registers a tool that runs arbitrary code/shell for the agent. Rarely fits a "
            "narrow business purpose and is a top target for abuse.",
            "Remove code/shell tools from user-facing agents, or gate them behind strict authz.",
        ),
        compile_sig(
            "AFW-AGENCY-003", "System prompt grants unrestricted scope", S.MEDIUM,
            r"(?i)you\s+(can|may|are\s+able\s+to|are\s+allowed\s+to)\s+"
            r"(do\s+anything|answer\s+any(thing|\s+question)|run\s+any\s+(code|command)|"
            r"execute\s+any|access\s+anything|help\s+with\s+anything)|"
            r"\bno\s+(restrictions|limits|limitations|guardrails|boundaries)\b|"
            r"\bunrestricted\s+(access|assistant|agent)\b",
            "The agent's instructions grant open-ended scope instead of confining it to its "
            "business function — the root of off-mission abuse (e.g. code exec on a food bot).",
            "Scope the agent explicitly: state what it may do and refuse everything else.",
            flags=0,
        ),
    ],
)

# All PatternRules exported for the registry.
PATTERN_RULES = [
    SECRETS, NETWORK, OBFUSCATION, DESTRUCTIVE, FILESYSTEM,
    EMBEDDED_SECRETS, DESERIALIZATION, OUTPUT_HANDLING, ANTI_FORENSICS,
    MEMORY_POISONING, AGENT_AGENCY,
]
