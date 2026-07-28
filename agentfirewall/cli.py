"""Command-line interface for AgentFirewall.

    afw scan    <path>...           inspect artifacts and print a report
    afw verify  <path>...           CI gate: non-zero exit if anything is blocked
    afw install <path> --to <dir>   pre-check, then install only if it passes
    afw watch   <dir>               monitor a directory and scan new artifacts
    afw rules                       list every detection the firewall runs
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from typing import Optional

from . import __version__, report
from .models import ScanResult, Severity, Verdict
from .policy import Policy
from .rules import all_rules
from .scanner import Scanner


# --------------------------------------------------------------------------- #
# Shared plumbing
# --------------------------------------------------------------------------- #
def _build_policy(args: argparse.Namespace) -> Policy:
    if getattr(args, "policy", None):
        policy = Policy.from_file(args.policy)
    elif getattr(args, "strict", False):
        policy = Policy.strict()
    else:
        policy = Policy.default()
    for rid in getattr(args, "ignore", None) or []:
        policy.ignore.add(rid)
    if getattr(args, "fail_on", None):
        policy.block_severity = Severity.from_name(args.fail_on)
    return policy


def _emit(results: list[ScanResult], args: argparse.Namespace) -> None:
    fmt = getattr(args, "format", "text")
    if fmt == "json":
        out = (report.render_json(results[0]) if len(results) == 1
               else report.render_json_many(results))
        print(out)
    elif fmt == "sarif":
        print(report.render_sarif(results, version=__version__))
    else:
        color = False if getattr(args, "no_color", False) else None
        for i, r in enumerate(results):
            if i:
                print("\n" + "─" * 60 + "\n")
            print(report.render_text(r, color=color, verbose=getattr(args, "verbose", False)))


def _worst(results: list[ScanResult]) -> Verdict:
    order = {Verdict.ALLOW: 0, Verdict.WARN: 1, Verdict.BLOCK: 2}
    worst = Verdict.ALLOW
    for r in results:
        if order[r.verdict] > order[worst]:
            worst = r.verdict
    return worst


def _scanner(args: argparse.Namespace) -> Scanner:
    return Scanner(policy=_build_policy(args))


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #
def cmd_scan(args: argparse.Namespace) -> int:
    scanner = _scanner(args)
    baseline = getattr(args, "baseline", None)
    results = [scanner.scan_path(p, baseline_path=baseline) for p in args.paths]
    _emit(results, args)
    if any(r.error for r in results):
        return 1
    return _worst(results).exit_code


def cmd_verify(args: argparse.Namespace) -> int:
    scanner = _scanner(args)
    baseline = getattr(args, "baseline", None)
    results = [scanner.scan_path(p, baseline_path=baseline) for p in args.paths]
    _emit(results, args)
    if any(r.error for r in results):
        return 1
    worst = _worst(results)
    fail_on_warn = getattr(args, "fail_on_warn", False)
    if worst is Verdict.BLOCK:
        return 2
    if worst is Verdict.WARN and fail_on_warn:
        return 2
    return 0


def cmd_install(args: argparse.Namespace) -> int:
    scanner = _scanner(args)
    result = scanner.scan_path(args.path, baseline_path=getattr(args, "baseline", None))
    _emit([result], args)

    if result.error:
        return 1

    dest_root = args.to
    target = os.path.join(dest_root, result.artifact.name)

    if result.verdict is Verdict.BLOCK and not args.force:
        _stderr(f"\n⛔ Installation BLOCKED by AgentFirewall — {args.path} was NOT copied to {target}.")
        _stderr("   Re-run with --force to override (not recommended).")
        return 2
    if result.verdict is Verdict.WARN and not (args.yes or args.force):
        if not _confirm(f"\nAgentFirewall raised warnings. Install {result.artifact.name} anyway?"):
            _stderr("Installation cancelled.")
            return 2

    try:
        _install_copy(args.path, target)
    except OSError as exc:
        _stderr(f"Install failed: {exc}")
        return 1

    forced = " (FORCED past firewall)" if (result.verdict is Verdict.BLOCK and args.force) else ""
    print(f"\n✓ Installed {result.artifact.name} → {target}{forced}")
    return 0


def cmd_pin(args: argparse.Namespace) -> int:
    from . import baseline

    scanner = _scanner(args)
    result = scanner.scan_path(args.path)
    if result.error:
        _stderr(f"error: {result.error}")
        return 1

    _emit([result], args)
    if result.verdict is Verdict.BLOCK and not args.force:
        _stderr("\n⛔ Refusing to pin a BLOCKED artifact — fix the findings first, "
                "or use --force to pin as-is.")
        return 2

    out = args.output
    if not out:
        out = (os.path.join(args.path, baseline.DEFAULT_LOCK_NAME)
               if os.path.isdir(args.path) else args.path + ".lock")
    written = baseline.write(out, result.artifact)
    n_files = sum(1 for sf in result.artifact.files if sf.sha256)
    print(f"\n✓ Pinned {result.artifact.name} → {written}  "
          f"({n_files} files hashed). Re-verify updates with:  "
          f"afw verify {args.path} --baseline {written}")
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    scanner = _scanner(args)
    directory = args.directory
    if not os.path.isdir(directory):
        _stderr(f"Not a directory: {directory}")
        return 1
    interval = max(1.0, args.interval)
    print(f"AgentFirewall monitoring {directory} (every {interval:g}s). Ctrl-C to stop.")
    seen: dict[str, float] = {}
    try:
        while True:
            for entry in sorted(os.listdir(directory)):
                full = os.path.join(directory, entry)
                try:
                    mtime = os.path.getmtime(full)
                except OSError:
                    continue
                if seen.get(full) == mtime:
                    continue
                seen[full] = mtime
                result = scanner.scan_path(full)
                icon = report._ICON[result.verdict]
                stamp = time.strftime("%H:%M:%S")
                print(f"[{stamp}] {icon} {result.verdict.value.upper():5} "
                      f"{entry}  ({sum(1 for _ in result.findings)} findings)")
                if result.verdict is not Verdict.ALLOW:
                    _emit([result], args)
            if args.once:
                break
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\nStopped.")
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    from .rules.base import PatternRule

    rows: list[dict] = []
    for rule in all_rules():
        if isinstance(rule, PatternRule):
            for sig in rule.signatures:
                rows.append({
                    "id": sig.id, "severity": sig.severity.label, "category": rule.category,
                    "title": sig.title,
                    "references": list(sig.references or rule.default_references),
                })
        else:
            rows.append({
                "id": rule.id + "-*", "severity": "varies", "category": rule.category,
                "title": type(rule).__name__, "references": [],
            })

    if getattr(args, "format", "text") == "json":
        import json
        print(json.dumps(rows, indent=2))
        return 0

    print(f"AgentFirewall {__version__} — {len(rows)} detections\n")
    width = max(len(r["id"]) for r in rows)
    cat_w = max(len(r["category"]) for r in rows)
    for r in rows:
        print(f"  {r['id']:<{width}}  {r['severity']:<8}  {r['category']:<{cat_w}}  {r['title']}")

    # Framework coverage summary.
    frameworks: dict[str, int] = {}
    for r in rows:
        for ref in r["references"]:
            fam = ref.split(":", 1)[0]
            frameworks[fam] = frameworks.get(fam, 0) + 1
    if frameworks:
        print("\nFramework coverage (detections mapped):")
        for fam in sorted(frameworks):
            print(f"  {fam:<14} {frameworks[fam]}")
    return 0


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _install_copy(src: str, target: str) -> None:
    os.makedirs(os.path.dirname(target) or ".", exist_ok=True)
    if os.path.isdir(src):
        if os.path.exists(target):
            shutil.rmtree(target)
        shutil.copytree(src, target)
    else:
        shutil.copy2(src, target)


def _confirm(prompt: str) -> bool:
    try:
        return input(f"{prompt} [y/N] ").strip().lower() in {"y", "yes"}
    except (EOFError, KeyboardInterrupt):
        return False


def _stderr(msg: str) -> None:
    print(msg, file=sys.stderr)


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="afw",
        description="AgentFirewall — inspect AI agents/skills/MCP servers before you trust them.",
    )
    parser.add_argument("--version", action="version", version=f"AgentFirewall {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser, with_format: bool = True) -> None:
        if with_format:
            p.add_argument("-f", "--format", choices=["text", "json", "sarif"],
                           default="text", help="output format (default: text)")
        p.add_argument("--policy", help="path to a policy file (JSON or YAML)")
        p.add_argument("--strict", action="store_true",
                       help="block on MEDIUM findings and above")
        p.add_argument("--fail-on", metavar="SEVERITY",
                       help="block at this severity or above (INFO/LOW/MEDIUM/HIGH/CRITICAL)")
        p.add_argument("--ignore", action="append", metavar="RULE_ID",
                       help="suppress a rule id or category (repeatable)")
        p.add_argument("--no-color", action="store_true", help="disable ANSI colour")
        p.add_argument("-v", "--verbose", action="store_true",
                       help="include remediation guidance")

    p_scan = sub.add_parser("scan", help="scan artifacts and print a report")
    p_scan.add_argument("paths", nargs="+", help="files, directories or .zip archives")
    p_scan.add_argument("--baseline", metavar="LOCK",
                        help="afw.lock to diff against (detects rug-pull drift)")
    add_common(p_scan)
    p_scan.set_defaults(func=cmd_scan)

    p_verify = sub.add_parser("verify", help="CI gate: exit non-zero on a blocked artifact")
    p_verify.add_argument("paths", nargs="+")
    p_verify.add_argument("--fail-on-warn", action="store_true",
                          help="also fail when the verdict is WARN")
    p_verify.add_argument("--baseline", metavar="LOCK",
                          help="afw.lock to diff against (detects rug-pull drift)")
    add_common(p_verify)
    p_verify.set_defaults(func=cmd_verify)

    p_install = sub.add_parser("install", help="pre-check, then install only if it passes")
    p_install.add_argument("path", help="artifact to install (dir/file/zip)")
    p_install.add_argument("--to", required=True, metavar="DIR",
                           help="destination directory to install into")
    p_install.add_argument("--force", action="store_true",
                           help="install even if BLOCKED (dangerous)")
    p_install.add_argument("--yes", action="store_true",
                           help="assume yes for WARN confirmations")
    p_install.add_argument("--baseline", metavar="LOCK",
                           help="afw.lock to diff against before installing")
    add_common(p_install)
    p_install.set_defaults(func=cmd_install)

    p_pin = sub.add_parser("pin", help="record a trusted baseline (afw.lock) for an artifact")
    p_pin.add_argument("path", help="artifact to pin (dir/file/zip)")
    p_pin.add_argument("-o", "--output", metavar="LOCK",
                       help="where to write the lock file (default: <artifact>/afw.lock)")
    p_pin.add_argument("--force", action="store_true",
                       help="pin even if the artifact is currently BLOCKED")
    add_common(p_pin)
    p_pin.set_defaults(func=cmd_pin)

    p_watch = sub.add_parser("watch", help="monitor a directory and scan new artifacts")
    p_watch.add_argument("directory")
    p_watch.add_argument("--interval", type=float, default=3.0,
                         help="poll interval in seconds (default: 3)")
    p_watch.add_argument("--once", action="store_true",
                         help="scan the current contents once and exit")
    add_common(p_watch)
    p_watch.set_defaults(func=cmd_watch)

    p_rules = sub.add_parser("rules", help="list every detection")
    p_rules.add_argument("-f", "--format", choices=["text", "json"], default="text")
    p_rules.set_defaults(func=cmd_rules)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        _stderr(f"error: {exc}")
        return 1
    except KeyboardInterrupt:  # pragma: no cover
        return 130


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
