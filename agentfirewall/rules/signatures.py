"""The signature library: regex-based detections grouped by category.

Each :class:`PatternRule` bundles a family of signatures. Keeping them here as
plain data makes the catalogue easy to audit and extend -- add a line, get a new
detection. Categories map to how a malicious agent artifact typically attacks the
host it is installed into.
"""
from __future__ import annotations

from ..models import Severity
from .base import PatternRule, compile_sig

S = Severity

# --------------------------------------------------------------------------- #
# 1. Secret & credential access / exfiltration
# --------------------------------------------------------------------------- #
SECRETS = PatternRule(
    id="secrets",
    category="secret-access",
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

# All PatternRules exported for the registry.
PATTERN_RULES = [SECRETS, NETWORK, OBFUSCATION, DESTRUCTIVE, FILESYSTEM]
