"""Stage redacted copies, re-scan them, write the manifest and the ZIP."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import tempfile
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import DISCLAIMER, __version__
from .discovery import DiscoveryResult, Session, SupportFile, is_credential_file
from .paths import display_path, safe_component
from .privacy import Finding, Redactor, process_file, rescan_file
from .timeutil import DateRange, iso


class ExportAborted(Exception):
    """Raised when a safety check fails; the message never contains content."""


@dataclass
class StagedFile:
    # No hash or size of the *original* bytes is kept: publishing them would
    # let anyone confirm guesses of redacted values (e.g. a phone number).
    arc: str
    kind: str
    source_label: str
    exported_sha256: str
    exported_bytes: int
    redactions: Counter
    omitted_lines: list
    note: Optional[str] = None


@dataclass
class StagedSession:
    session: Session
    files: List[StagedFile] = field(default_factory=list)
    skipped: List[tuple] = field(default_factory=list)


@dataclass
class StageResult:
    staging_dir: Path
    sessions: List[StagedSession] = field(default_factory=list)
    dropped: List[tuple] = field(default_factory=list)  # (session, reason)
    findings: List[Finding] = field(default_factory=list)
    totals: Counter = field(default_factory=Counter)
    used_arcs: set = field(default_factory=set)

    def unique_arc(self, arc: str) -> str:
        """Avoid collisions between names that sanitize to the same string."""
        candidate, n = arc, 2
        while candidate.lower() in self.used_arcs:  # lower(): case-insensitive file systems
            stem, dot, ext = arc.rpartition(".")
            candidate = f"{stem}~{n}.{ext}" if dot and "/" not in ext else f"{arc}~{n}"
            n += 1
        self.used_arcs.add(candidate.lower())
        return candidate

    @property
    def file_count(self) -> int:
        return sum(len(s.files) for s in self.sessions)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _write(staging: Path, arc: str, data: bytes) -> None:
    target = staging.joinpath(*arc.split("/"))
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "xb") as fh:  # "x": never overwrite anything
        fh.write(data)


def _stage_one(staging: Path, arc: str, raw: bytes, kind: str, label: str,
               redactor: Redactor, result: StageResult, note: Optional[str] = None):
    res = process_file(raw, arc, redactor)
    if res.data is None:
        return None, res.excluded_reason or "could not be processed"
    arc = result.unique_arc(arc)
    _write(staging, arc, res.data)
    result.findings.extend(res.locations)
    result.totals.update(res.counts)
    return StagedFile(
        arc=arc, kind=kind, source_label=label, exported_sha256=_sha256(res.data),
        exported_bytes=len(res.data), redactions=res.counts, omitted_lines=res.omitted_lines,
        note=note), None


def _session_base(s: Session) -> str:
    return f"{s.tool}/{safe_component(s.session_id)}"


def stage(discovery: DiscoveryResult, redactor: Redactor, staging: Path) -> StageResult:
    result = StageResult(staging_dir=staging)
    used_bases = set()
    for s in discovery.by_status("selected"):
        base = _session_base(s)
        while base in used_bases:
            base += "_"
        used_bases.add(base)
        staged = StagedSession(s, skipped=list(s.skipped_support))
        try:
            raw = s.source.read_bytes()[: s.scanned_bytes]
        except OSError as exc:
            result.dropped.append((s, f"session file could not be read ({type(exc).__name__})"))
            continue
        if _sha256(raw) != s.scanned_sha256:
            # Appends are fine (only the scanned prefix is exported), but a
            # rewritten file no longer matches what was attributed.
            result.dropped.append((s, "session file changed during export; run again"))
            continue
        main_arc = f"{base}/{safe_component(s.source.name)}"
        label = display_path(s.source)
        sf, err = _stage_one(staging, main_arc, raw, "session", label, redactor, result)
        if sf is None:
            result.dropped.append((s, f"session file excluded: {err}"))
            continue
        staged.files.append(sf)
        for sup in s.support:
            _stage_support(staging, base, sup, staged, redactor, result)
        result.sessions.append(staged)
    return result


def _stage_support(staging: Path, base: str, sup: SupportFile, staged: StagedSession,
                   redactor: Redactor, result: StageResult) -> None:
    name = sup.arc_rel.rsplit("/", 1)[-1]
    if is_credential_file(name) or (sup.source is not None and is_credential_file(sup.source.name)):
        staged.skipped.append((sup.arc_rel, "credential or authentication file"))
        return
    if sup.data is not None:
        raw = sup.data
    else:
        try:
            raw = sup.source.read_bytes()
        except OSError as exc:
            staged.skipped.append((sup.arc_rel, f"could not be read ({type(exc).__name__})"))
            return
    arc = f"{base}/{sup.arc_rel}"
    sf, err = _stage_one(staging, arc, raw, sup.kind, sup.label, redactor, result, sup.note)
    if sf is None:
        staged.skipped.append((sup.arc_rel, err))
    else:
        staged.files.append(sf)


def rescan_staging(result: StageResult, redactor: Redactor,
                   extra: List[str] = ()) -> Tuple[List[str], Dict[str, str]]:
    """Re-scan every staged file.

    Returns content-free problem descriptions and the SHA-256 of every file
    exactly as it was scanned; the ZIP must contain exactly those bytes.
    """
    expected = {f.arc for s in result.sessions for f in s.files} | set(extra)
    problems: List[str] = []
    hashes: Dict[str, str] = {}
    seen = set()
    for dirpath, _, filenames in os.walk(result.staging_dir):
        for name in filenames:
            p = Path(dirpath, name)
            arc = p.relative_to(result.staging_dir).as_posix()
            seen.add(arc)
            if arc not in expected:
                problems.append(f"{arc}: unexpected file in staging area")
                continue
            if is_credential_file(name):
                problems.append(f"{arc}: credential file name")
                continue
            if redactor.scan_text(arc):
                problems.append(f"{arc}: archive path contains sensitive text")
            data = p.read_bytes()
            hashes[arc] = _sha256(data)
            problems.extend(rescan_file(data, arc, redactor))
    for arc in sorted(expected - seen):
        problems.append(f"{arc}: missing from staging area")
    return problems, hashes


def _session_entry(s: Session) -> dict:
    entry = {"tool": s.tool, "session_id": s.session_id}
    if s.touches_repo:  # never describe activity of other projects
        entry.update({"started_at": iso(s.first_ts), "ended_at": iso(s.last_ts)})
    return entry


def build_manifest(discovery: DiscoveryResult, result: StageResult, rng: DateRange,
                   repo: str, tools: List[str], redactor: Redactor, options: dict) -> dict:
    sessions = []
    for st in result.sessions:
        s = st.session
        entry = _session_entry(s)
        entry.update({
            "working_directories": s.cwds,
            "repository_match": s.match,
            "event_count": s.event_count,
            "events_in_range": s.events_in_range,
            "multi_day": bool(s.first_ts and s.last_ts and s.first_ts.date() != s.last_ts.date()),
            "warnings": s.warnings,
            "files": [{
                "archive_path": f.arc,
                "kind": f.kind,
                "source": f.source_label,
                "exported_sha256": f.exported_sha256,
                "exported_bytes": f.exported_bytes,
                "redactions": dict(sorted(f.redactions.items())),
                "omitted_lines": [{"line": n, "reason": r} for n, r in f.omitted_lines],
                **({"note": f.note} if f.note else {}),
            } for f in st.files],
            "skipped_files": [{"path": p, "reason": r} for p, r in st.skipped],
        })
        sessions.append(entry)
    excluded = []
    for s in discovery.sessions:
        if s.status in ("excluded", "unattributable"):
            e = _session_entry(s)
            e["reason"] = s.reason
            excluded.append(e)
    for s, reason in result.dropped:
        e = _session_entry(s)
        e["reason"] = reason
        excluded.append(e)
    manifest = {
        "format_version": 1,
        "generator": {"name": "session-exporter", "version": __version__},
        "created_at": iso(datetime.now(timezone.utc)),
        "platform": {"system": platform.system(), "python": platform.python_version()},
        "query": {"tools": tools, "repository": repo, "date_range": rng.describe(), **options},
        "summary": {
            "sessions_exported": len(sessions),
            "files_exported": result.file_count,
            "sessions_excluded": len(excluded),
            "repository_sessions_out_of_range": len(discovery.by_status("out_of_range")),
            "other_or_unattributable_session_files_skipped": dict(sorted(discovery.unrelated.items())),
        },
        "privacy": {
            "redaction_applied": True,
            "final_rescan": "passed",
            "redactions_by_detector": dict(sorted(result.totals.items())),
            "detectors": redactor.detector_names(),
            "placeholder_format": "[REDACTED:<detector>]; home directory shown as ~",
            "omitted_line_record_type": "session_exporter.omitted_line",
            "disclaimer": DISCLAIMER,
        },
        "sessions": sessions,
        "excluded_sessions": excluded,
        "warnings": discovery.warnings,
    }
    # The manifest itself goes through the redactor (it contains paths).
    redacted, _ = redactor.redact_obj(manifest)
    return redacted


def write_manifest(result: StageResult, manifest: dict) -> None:
    data = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
    _write(result.staging_dir, "manifest.json", data)


def make_staging_dir() -> Path:
    # mkdtemp creates the directory readable only by the current user.
    return Path(tempfile.mkdtemp(prefix="session-export-"))


def remove_staging(staging: Path) -> None:
    shutil.rmtree(staging, ignore_errors=True)


def write_zip(result: StageResult, output: Path, force: bool, scanned: Dict[str, str]) -> None:
    """Write the ZIP from staged files whose bytes match the final re-scan."""
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists() and not force:
        raise ExportAborted(f"{display_path(output)} already exists (use --force to overwrite)")
    tmp = output.with_name("." + output.name + ".partial")
    arcs = ["manifest.json"] + sorted(f.arc for s in result.sessions for f in s.files)
    if set(arcs) != set(scanned):
        raise ExportAborted("staged file list differs from the re-scanned list")
    expected = {}
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for arc in arcs:
                data = result.staging_dir.joinpath(*arc.split("/")).read_bytes()
                if _sha256(data) != scanned[arc]:
                    raise ExportAborted(f"{arc} changed after the final re-scan")
                expected[arc] = scanned[arc]
                zf.writestr(arc, data)
        # Verify the archive contains exactly the re-scanned bytes.
        with zipfile.ZipFile(tmp) as zf:
            names = zf.namelist()
            if sorted(names) != sorted(arcs):
                raise ExportAborted("archive verification failed: unexpected entries")
            for arc in names:
                if _sha256(zf.read(arc)) != expected[arc]:
                    raise ExportAborted("archive verification failed: content mismatch")
        os.replace(tmp, output)
    finally:
        if tmp.exists():
            tmp.unlink()
