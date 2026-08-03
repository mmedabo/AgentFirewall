"""Turn a target path into an :class:`Artifact` the scanner can inspect.

Supports directories, single files and ``.zip`` archives. Recognises the common
AI-agent artifact shapes -- Claude-style skills (``SKILL.md``), agent definition
markdown, and MCP server JSON configs -- and extracts their declared tools and
permissions so structural rules can reason about over-broad access.

The loader is intentionally dependency-free: it ships a tiny YAML-frontmatter
reader that understands only the handful of fields we need, so ``pip install
agentfirewall`` pulls in nothing.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import zipfile
from typing import Any, Iterable, Optional

from .models import Artifact, ScannedFile

# Files we never try to read as text.
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".whl", ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".class",
    ".mp3", ".mp4", ".mov", ".woff", ".woff2", ".ttf", ".otf", ".jar",
}
# Directories that are noise, not artifact content.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}
# Files that are AgentFirewall's own metadata, not part of the artifact.
_SKIP_FILES = {"afw.lock"}

_MAX_FILE_BYTES = 2_000_000  # 2 MB: bigger text files are almost always data.


def load(path: str) -> Artifact:
    """Load ``path`` (dir, file or zip) into an :class:`Artifact`."""
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    if os.path.isdir(path):
        artifact = _load_dir(path)
    elif zipfile.is_zipfile(path):
        artifact = _load_zip(path)
    else:
        artifact = _load_single(path)

    _classify(artifact)
    return artifact


# --------------------------------------------------------------------------- #
# Sources
# --------------------------------------------------------------------------- #
def _load_dir(root: str) -> Artifact:
    files: list[ScannedFile] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            if name in _SKIP_FILES:
                continue
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            files.append(_read_file(rel, full))
    return Artifact(name=os.path.basename(root.rstrip("/")) or root, root=root,
                    kind="directory", files=files)


def _load_zip(path: str) -> Artifact:
    files: list[ScannedFile] = []
    with zipfile.ZipFile(path) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            parts = info.filename.split("/")
            if any(part in _SKIP_DIRS for part in parts) or parts[-1] in _SKIP_FILES:
                continue
            data = zf.read(info) if info.file_size <= _MAX_FILE_BYTES else b""
            files.append(_read_bytes(info.filename, data,
                                     truncated=info.file_size > _MAX_FILE_BYTES))
    return Artifact(name=os.path.basename(path), root=path, kind="archive", files=files)


def _load_single(path: str) -> Artifact:
    rel = os.path.basename(path)
    sf = _read_file(rel, path)
    return Artifact(name=rel, root=os.path.dirname(path) or ".", kind="file", files=[sf])


# --------------------------------------------------------------------------- #
# File reading
# --------------------------------------------------------------------------- #
def _read_file(rel: str, full: str) -> ScannedFile:
    role = _role_for(rel)
    try:
        size = os.path.getsize(full)
    except OSError:
        size = 0
    # Large or clearly-binary files: stream-hash them but don't load as text.
    if _looks_binary(rel) or size > _MAX_FILE_BYTES:
        return ScannedFile(path=rel, text="", is_binary=True, role=role,
                           sha256=_hash_path(full))
    try:
        with open(full, "rb") as fh:
            data = fh.read()
    except OSError:
        return ScannedFile(path=rel, text="", is_binary=True, role=role)
    return _read_bytes(rel, data)


def _read_bytes(rel: str, data: bytes, truncated: bool = False) -> ScannedFile:
    role = _role_for(rel)
    digest = hashlib.sha256(data).hexdigest() if data else ""
    if _looks_binary(rel) or b"\x00" in data[:8192] or truncated:
        return ScannedFile(path=rel, text="", is_binary=True, role=role, sha256=digest)
    text = data.decode("utf-8", errors="replace")
    return ScannedFile(path=rel, text=text, is_binary=False, role=role, sha256=digest)


def _hash_path(full: str) -> str:
    h = hashlib.sha256()
    try:
        with open(full, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
    except OSError:
        return ""
    return h.hexdigest()


def _looks_binary(rel: str) -> bool:
    return os.path.splitext(rel)[1].lower() in _BINARY_EXTS


def _role_for(rel: str) -> str:
    name = os.path.basename(rel).lower()
    ext = os.path.splitext(name)[1]
    if name in {"skill.md", "agent.md", "plugin.json", "manifest.json",
                "mcp.json", ".mcp.json", "package.json"} or name.endswith(".mcp.json"):
        return "manifest"
    if ext in {".md", ".mdx", ".txt", ".rst"}:
        return "doc"
    if ext in {".sh", ".bash", ".zsh", ".py", ".js", ".ts", ".rb", ".pl", ".ps1"}:
        return "script"
    if ext in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg"}:
        return "config"
    return "file"


# --------------------------------------------------------------------------- #
# Classification & manifest parsing
# --------------------------------------------------------------------------- #
def _classify(artifact: Artifact) -> None:
    """Refine ``kind`` and pull declared tools/permissions into metadata."""
    by_name = {os.path.basename(f.path).lower(): f for f in artifact.files}

    manifest = None
    for candidate in ("skill.md", "agent.md"):
        if candidate in by_name:
            manifest = by_name[candidate]
            artifact.kind = "skill" if candidate == "skill.md" else "agent"
            break

    if manifest is not None:
        fm = _parse_frontmatter(manifest.text)
        artifact.metadata["manifest_path"] = manifest.path
        artifact.metadata["declared_tools"] = _as_list(
            fm.get("allowed-tools") or fm.get("tools"))
        artifact.metadata["declared_permissions"] = _as_list(fm.get("allowed-tools"))
        if fm.get("name"):
            artifact.metadata["declared_name"] = fm["name"]

    # MCP config discovery.
    for name, sf in by_name.items():
        if name.endswith("mcp.json") or name in {"mcp.json", ".mcp.json"}:
            if artifact.kind in {"directory", "file", "unknown"}:
                artifact.kind = "mcp"
            _parse_mcp(sf.text, artifact)
        elif name in {"plugin.json", "manifest.json"} and artifact.kind == "directory":
            artifact.kind = "plugin"


def _parse_frontmatter(text: str) -> dict[str, Any]:
    """Minimal YAML-frontmatter reader for the fields the rules need.

    Handles ``key: value``, inline lists ``key: [a, b]`` / ``key: a, b`` and
    block lists (``key:`` followed by ``- item`` lines). Good enough for skill
    and agent headers without a YAML dependency.
    """
    if not text.startswith("---"):
        return {}
    lines = text.splitlines()
    if not lines:
        return {}
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() in ("---", "..."):
            end = i
            break
    if end is None:
        return {}

    out: dict[str, Any] = {}
    current_key: str | None = None
    for raw in lines[1:end]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        stripped = raw.strip()
        if stripped.startswith("- ") and current_key is not None:
            out.setdefault(current_key, [])
            if isinstance(out[current_key], list):
                out[current_key].append(stripped[2:].strip().strip("\"'"))
            continue
        if ":" in raw and not raw.startswith(" "):
            key, _, value = raw.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key
            if value == "":
                out[key] = []  # possibly a block list to follow
            else:
                out[key] = value.strip("\"'")
    return out


_SECRET_ENV_HINT = re.compile(r"(key|token|secret|password|passwd|credential)", re.IGNORECASE)
_REMOTE_TRANSPORTS = {"http", "https", "sse", "streamable-http", "streamable_http", "ws", "wss"}
_AUTH_HINT = re.compile(r"auth|authorization|bearer|token|api[-_]?key|credential",
                        re.IGNORECASE)


def _mcp_auth_risk(sname: str, cfg: dict) -> Optional[dict]:
    """Flag a remote MCP server configured with no authentication."""
    url = str(cfg.get("url") or cfg.get("endpoint") or cfg.get("serverUrl") or "")
    transport = str(cfg.get("type") or cfg.get("transport") or "").lower()
    is_remote = bool(url) or transport in _REMOTE_TRANSPORTS
    if not is_remote:
        return None  # stdio/command servers aren't network-exposed

    # Any sign of auth on the connection?
    blob = json.dumps(cfg)
    headers = cfg.get("headers")
    has_header_auth = isinstance(headers, dict) and any(_AUTH_HINT.search(k) for k in headers)
    has_field_auth = any(_AUTH_HINT.search(k) for k in cfg if k not in ("url", "endpoint"))
    has_url_creds = "@" in url.split("//", 1)[-1].split("/", 1)[0]  # user:pass@host
    authed = has_header_auth or has_field_auth or has_url_creds or bool(_AUTH_HINT.search(blob))

    plaintext = url.startswith("http://")
    if authed and not plaintext:
        return None

    if not authed:
        msg = (f"Remote MCP server '{sname}' is configured with no authentication"
               + (" and over plaintext http://" if plaintext else "")
               + ". Unauthenticated MCP endpoints let anyone who can reach them drive the "
                 "agent's tools (cf. the 2026 MCP CVEs and 400+ exposed public servers).")
    else:
        msg = (f"Remote MCP server '{sname}' is reached over plaintext http:// — "
               "credentials and tool traffic are exposed in transit.")
    return {
        "rule_id": "AFW-MCP-003",
        "title": "Remote MCP server without authentication",
        "severity": "HIGH" if not authed else "MEDIUM",
        "message": msg,
        "evidence": (url or f"{sname}: {transport or 'remote'}")[:160],
        "remediation": "Require authentication (bearer token / API key) and use https; "
                       "never expose an MCP endpoint that executes tools without authz.",
        "references": ["OWASP-ASI03:Identity-and-Privilege-Abuse",
                       "OWASP-API:Broken-Function-Level-Authorization",
                       "OWASP-ASI04:Agentic-Supply-Chain"],
    }


def _parse_mcp(text: str, artifact: Artifact) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return
    if not isinstance(data, dict):
        return
    servers = data.get("mcpServers") or data.get("servers") or {}
    if isinstance(servers, dict) and servers:
        artifact.metadata.setdefault("mcp_servers", list(servers.keys()))

    risks = artifact.metadata.setdefault("mcp_risks", [])
    tool_descs = artifact.metadata.setdefault("tool_descriptions", [])

    if isinstance(servers, dict):
        for sname, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            env = cfg.get("env")
            if isinstance(env, dict):
                for k, v in env.items():
                    if _SECRET_ENV_HINT.search(str(k)) and str(v).strip() and \
                            not str(v).startswith("${"):
                        risks.append({
                            "rule_id": "AFW-MCP-001",
                            "title": "Secret hard-coded in MCP server env",
                            "severity": "HIGH",
                            "message": f"MCP server '{sname}' embeds a secret in its env "
                                       f"('{k}') instead of referencing it indirectly.",
                            "evidence": f"{k}=<redacted>",
                            "remediation": "Reference secrets via ${ENV_VAR}; never inline them.",
                        })
            for key in ("autoApprove", "alwaysAllow", "auto_approve"):
                approved = cfg.get(key)
                if approved:
                    risks.append({
                        "rule_id": "AFW-MCP-002",
                        "title": "MCP server auto-approves tool calls",
                        "severity": "MEDIUM",
                        "message": f"MCP server '{sname}' sets '{key}', letting tools run "
                                   "without per-call confirmation.",
                        "evidence": f"{key}: {approved}",
                        "remediation": "Require explicit approval for tool calls.",
                    })

            # Remote MCP server reached without authentication (ASI03/ASI05).
            # 2026 saw many MCP CVEs and 400+ public MCP servers exposed with no auth.
            risk = _mcp_auth_risk(sname, cfg)
            if risk:
                risks.append(risk)

    # Tool descriptions can appear in server-manifest style configs.
    tools = data.get("tools")
    if isinstance(tools, list):
        for t in tools:
            if isinstance(t, dict) and t.get("description"):
                tool_descs.append({"name": t.get("name", "?"),
                                   "text": str(t["description"])})


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    s = str(value).strip()
    if s.startswith("[") and s.endswith("]"):
        s = s[1:-1]
    parts: Iterable[str] = (p.strip().strip("\"'") for p in s.split(","))
    return [p for p in parts if p]
