"""Command-line interface."""

from __future__ import annotations

import argparse
import signal
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from . import DISCLAIMER, __version__
from .discovery import DiscoveryResult, claude_home, codex_home, discover
from .exporter import (ExportAborted, build_manifest, make_staging_dir, remove_staging,
                       rescan_staging, stage, write_manifest, write_zip)
from .paths import RepoMatcher, display_path, is_absolute_any
from .privacy import CATEGORIES, Redactor
from .timeutil import DateRange, parse_date, resolve_timezone

EXIT_OK, EXIT_NOTHING, EXIT_USAGE, EXIT_UNSAFE, EXIT_CANCELLED = 0, 1, 2, 3, 4


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="session-exporter",
        description="Export Codex / Claude Code sessions for one repository and date range "
                    "into a redacted ZIP archive. Everything runs locally; nothing is uploaded.",
        epilog=DISCLAIMER,
    )
    p.add_argument("--tool", choices=["codex", "claude", "both"], default="both",
                   help="which agent's sessions to export (default: both)")
    p.add_argument("--repo", required=True, help="absolute path of the project repository")
    p.add_argument("--from", dest="date_from", required=True, metavar="YYYY-MM-DD",
                   help="first day of the range (inclusive)")
    p.add_argument("--to", dest="date_to", required=True, metavar="YYYY-MM-DD",
                   help="last day of the range (inclusive)")
    p.add_argument("--output", help="path of the ZIP file to create (required unless --dry-run)")
    p.add_argument("--dry-run", action="store_true",
                   help="preview selected sessions and privacy findings; write nothing")
    p.add_argument("--yes", action="store_true",
                   help="skip the interactive review confirmation")
    p.add_argument("--force", action="store_true", help="overwrite an existing output file")
    p.add_argument("--timezone", default="local",
                   help="time zone for interpreting --from/--to: 'local' (default), 'UTC' "
                        "or an IANA name such as Asia/Seoul")
    p.add_argument("--exact", action="store_true",
                   help="only sessions started exactly in --repo (not in its subdirectories)")
    p.add_argument("--path-case", choices=["auto", "sensitive", "insensitive"], default="auto",
                   help="case sensitivity for POSIX path matching (default: detect from the "
                        "file system; Windows paths are always case-insensitive)")
    p.add_argument("--redact-term", action="append", default=[], metavar="TEXT",
                   help="extra text to redact, e.g. your name or student ID (repeatable)")
    p.add_argument("--keep-paths", action="store_true",
                   help="do not replace home-directory paths and user names")
    p.add_argument("--no-file-history", action="store_true",
                   help="do not include Claude Code file-history backups")
    p.add_argument("--show-all-findings", action="store_true",
                   help="list every finding location instead of the first 50")
    p.add_argument("--codex-home", help="Codex data directory (default: $CODEX_HOME or ~/.codex)")
    p.add_argument("--claude-home",
                   help="Claude Code data directory (default: $CLAUDE_CONFIG_DIR or ~/.claude)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


class _Printer:
    def __init__(self, tz_name: str):
        self.tz = resolve_timezone(tz_name)

    def time(self, ts: Optional[datetime]) -> str:
        if ts is None:
            return "-"
        local = ts.astimezone(self.tz) if self.tz else ts.astimezone()
        return local.strftime("%Y-%m-%d %H:%M")


def _print_discovery(d: DiscoveryResult, out: _Printer) -> None:
    selected = d.by_status("selected")
    print(f"\nSelected sessions: {len(selected)}")
    if selected:
        print(f"  {'TOOL':<7} {'SESSION ID':<38} {'START':<17} {'END':<17} {'MATCH':<12} EVENTS")
        for s in selected:
            print(f"  {s.tool:<7} {s.session_id:<38} {out.time(s.first_ts):<17} "
                  f"{out.time(s.last_ts):<17} {s.match or '-':<12} {s.event_count}")
            for w in s.warnings:
                print(f"          warning: {w}")
    excluded = [s for s in d.sessions if s.status in ("excluded", "unattributable")]
    if excluded:
        print(f"\nExcluded sessions (could not be confidently attributed): {len(excluded)}")
        for s in excluded:
            print(f"  {s.tool:<7} {s.session_id:<38} {s.reason}")
    oor = d.by_status("out_of_range")
    if oor:
        print(f"\nRepository sessions outside the date range: {len(oor)}")
    other = {k: v for k, v in d.unrelated.items() if not k.endswith("_unattributable")}
    unknown = {k[: -len("_unattributable")]: v for k, v in d.unrelated.items()
               if k.endswith("_unattributable")}
    if other:
        parts = ", ".join(f"{k}: {v}" for k, v in sorted(other.items()))
        print(f"Sessions from other projects (ignored): {parts}")
    if unknown:
        parts = ", ".join(f"{k}: {v}" for k, v in sorted(unknown.items()))
        print(f"Session files with no usable project metadata, nothing links them to this "
              f"repository (ignored, not listed): {parts}")
    for w in d.warnings:
        print(f"warning: {w}")


def _print_findings(result, show_all: bool) -> None:
    totals: Counter = result.totals
    print("\nPrivacy findings (redacted in the export):")
    if not totals:
        print("  none detected")
    else:
        for name, n in sorted(totals.items(), key=lambda kv: (CATEGORIES.get(kv[0], ""), kv[0])):
            print(f"  {CATEGORIES.get(name, 'secret'):<7} {name:<24} {n}")
    locs = result.findings
    if locs:
        limit = len(locs) if show_all else 50
        print(f"\nFinding locations ({min(limit, len(locs))} of {len(locs)}; "
              "home-directory paths not listed; values are never shown):")
        for f in locs[:limit]:
            where = f.file + (f":{f.line}" if f.line else "")
            print(f"  {where}  {f.json_path or ''}  {f.detector}")
    for st in result.sessions:
        for f in st.files:
            if f.omitted_lines:
                print(f"  note: {f.arc}: {len(f.omitted_lines)} line(s) replaced by "
                      "placeholder records (could not be parsed or redacted)")
        for path, reason in st.skipped:
            print(f"  skipped: {st.session.tool}/{st.session.session_id}/{path}: {reason}")
    for s, reason in result.dropped:
        print(f"  dropped session {s.tool}/{s.session_id}: {reason}")


def _confirm(prompt: str) -> bool:
    if not sys.stdin or not sys.stdin.isatty():
        return False
    try:
        return input(prompt).strip().lower() in ("y", "yes")
    except EOFError:
        return False


def _prepare_console() -> None:
    # Never crash on characters the console encoding cannot show.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except (AttributeError, ValueError):
            pass
    # Turn SIGTERM into a normal exit so the staging folder is cleaned up.
    try:
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(EXIT_CANCELLED))
    except (ValueError, OSError):  # not in the main thread / unsupported
        pass


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _prepare_console()

    def fail(msg: str) -> int:
        print(f"error: {msg}", file=sys.stderr)
        return EXIT_USAGE

    if not is_absolute_any(args.repo):
        return fail("--repo must be an absolute path")
    try:
        rng = DateRange(parse_date(args.date_from), parse_date(args.date_to), args.timezone)
        matcher = RepoMatcher(args.repo, args.path_case)
    except ValueError as exc:
        return fail(str(exc))
    output: Optional[Path] = None
    if not args.dry_run:
        if not args.output:
            return fail("--output is required unless --dry-run is given")
        output = Path(args.output).expanduser().resolve()
        if output.suffix.lower() != ".zip":
            return fail("--output must end with .zip")
        for home in (codex_home(args.codex_home), claude_home(args.claude_home)):
            if _is_within(output, home.expanduser().resolve()):
                return fail("--output must not be inside the Codex or Claude data directory")
        if output.exists() and not args.force:
            return fail(f"{display_path(output)} already exists (use --force to overwrite)")

    tools = ["codex", "claude"] if args.tool == "both" else [args.tool]
    redactor = Redactor(args.redact_term, redact_paths=not args.keep_paths)
    printer = _Printer(args.timezone)

    print(f"session-exporter {__version__}{'  [DRY RUN: nothing will be written]' if args.dry_run else ''}")
    print(f"Repository: {display_path(args.repo)}"
          + ("" if matcher.exists else "  (not found on this machine; matching recorded paths only)"))
    print(f"Date range: {args.date_from} .. {args.date_to} ({args.timezone})   Tools: {', '.join(tools)}")

    disc = discover(tools, matcher, rng, exact=args.exact, codex_dir=args.codex_home,
                    claude_dir=args.claude_home, include_file_history=not args.no_file_history)
    _print_discovery(disc, printer)
    if not disc.by_status("selected"):
        print("\nNo sessions to export.")
        return EXIT_NOTHING

    staging = make_staging_dir()
    try:
        result = stage(disc, redactor, staging)
        if not result.sessions:
            _print_findings(result, args.show_all_findings)
            print("\nNo sessions could be processed safely; nothing to export.")
            return EXIT_NOTHING
        options = {"exact": args.exact, "file_history": not args.no_file_history,
                   "path_redaction": not args.keep_paths,
                   "custom_terms": len(args.redact_term)}
        manifest = build_manifest(disc, result, rng, args.repo, tools, redactor, options)
        write_manifest(result, manifest)
        problems, scanned = rescan_staging(result, redactor, extra=["manifest.json"])
        _print_findings(result, args.show_all_findings)

        print("\nFinal re-scan of all export files: " + ("FAILED" if problems else "passed"))
        if problems:
            for p in problems[:50]:
                print(f"  {p}")
            print("Export aborted: no archive was created.", file=sys.stderr)
            return EXIT_UNSAFE
        print(f"\nNOTE: {DISCLAIMER}")
        if args.dry_run:
            print("\nDry run complete: no archive was written "
                  "(temporary staging files have been deleted).")
            return EXIT_OK

        print(f"\nReview: {len(result.sessions)} session(s), {result.file_count} file(s) "
              "plus manifest.json.")
        print(f"Redacted copies are staged for inspection at: {staging}")
        if not args.yes and not _confirm(f"Create {display_path(output)}? [y/N] "):
            print("Cancelled: no archive was created. (Use --yes in non-interactive shells.)")
            return EXIT_CANCELLED
        # The staging folder was open for inspection: make sure nothing in it
        # changed since the re-scan, then archive exactly those bytes.
        problems, after = rescan_staging(result, redactor, extra=["manifest.json"])
        if problems or after != scanned:
            print("Export aborted: staged files changed during the review; no archive was "
                  "created. Run the export again (use --redact-term for extra redactions).",
                  file=sys.stderr)
            return EXIT_UNSAFE
        write_zip(result, output, args.force, scanned)
        print(f"Created {display_path(output)}")
        return EXIT_OK
    except ExportAborted as exc:
        print(f"Export aborted: {exc}", file=sys.stderr)
        return EXIT_UNSAFE
    finally:
        remove_staging(staging)
