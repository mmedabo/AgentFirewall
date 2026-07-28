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

import json
import os
import zipfile
from typing import Any, Iterable

from .models import Artifact, ScannedFile

# Files we never try to read as text.
_BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz",
    ".tar", ".whl", ".so", ".dylib", ".dll", ".exe", ".bin", ".pyc", ".class",
    ".mp3", ".mp4", ".mov", ".woff", ".woff2", ".ttf", ".otf", ".jar",
}
# Directories that are noise, not artifact content.
_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}

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
            if any(part in _SKIP_DIRS for part in info.filename.split("/")):
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
    try:
        size = os.path.getsize(full)
    except OSError:
        size = 0
    if _looks_binary(rel) or size > _MAX_FILE_BYTES:
        return ScannedFile(path=rel, text="", is_binary=True, role=_role_for(rel))
    try:
        with open(full, "rb") as fh:
            data = fh.read()
    except OSError:
        return ScannedFile(path=rel, text="", is_binary=True, role=_role_for(rel))
    return _read_bytes(rel, data)


def _read_bytes(rel: str, data: bytes, truncated: bool = False) -> ScannedFile:
    role = _role_for(rel)
    if _looks_binary(rel) or b"\x00" in data[:8192] or truncated:
        return ScannedFile(path=rel, text="", is_binary=True, role=role)
    text = data.decode("utf-8", errors="replace")
    return ScannedFile(path=rel, text=text, is_binary=False, role=role)


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


def _parse_mcp(text: str, artifact: Artifact) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return
    servers = {}
    if isinstance(data, dict):
        servers = data.get("mcpServers") or data.get("servers") or {}
    if isinstance(servers, dict) and servers:
        artifact.metadata.setdefault("mcp_servers", list(servers.keys()))


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
