"""Find Codex and Claude Code sessions and attribute them to a repository.

Only fields verified against real session files are used:

Codex (``$CODEX_HOME`` or ``~/.codex``)
    ``sessions/YYYY/MM/DD/rollout-<local time>-<uuid>.jsonl`` and
    ``archived_sessions/``. Records are ``{timestamp, type, payload}``. The
    first record is ``session_meta`` whose ``payload.id`` equals the UUID in
    the file name and whose ``payload.cwd`` is the working directory.
    ``turn_context`` records repeat ``payload.cwd``. Later ``session_meta``
    records describe parent/forked threads. Global ``history.jsonl`` lines
    carry ``session_id``; ``session_index.jsonl`` lines carry ``id``.

Claude Code (``$CLAUDE_CONFIG_DIR`` or ``~/.claude``)
    ``projects/<encoded cwd>/<sessionId>.jsonl``; records carry ``cwd``,
    ``sessionId`` and ``timestamp``. ``projects/<dir>/<sessionId>/`` holds
    supporting files (tool results, subagents). ``file-history/<sessionId>/``
    holds file backups mapped to original paths by ``file-history-snapshot``
    and ``file-history-delta`` records. Global ``history.jsonl`` lines carry
    ``sessionId``.
"""

from __future__ import annotations

import hashlib
import json
import ntpath
import os
import posixpath
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

from .paths import (RepoMatcher, claude_project_dirname, display_path, is_windows_path,
                    safe_component)
from .timeutil import DateRange, parse_timestamp

UUID_IN_NAME = re.compile(r"([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\.jsonl$")

# Files that must never be exported, wherever they are found.
CREDENTIAL_NAMES = {
    "auth.json", ".credentials.json", "credentials.json", "credentials", "config.toml",
    "settings.json", "settings.local.json", ".netrc", "_netrc", ".npmrc", ".pypirc", ".pgpass",
    ".envrc", ".htpasswd", ".git-credentials", "kubeconfig", ".dockerconfigjson", "id_rsa",
    "id_dsa", "id_ecdsa", "id_ed25519",
}
CREDENTIAL_SUFFIXES = (
    ".key", ".pem", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ovpn", ".sqlite",
    ".sqlite-wal", ".sqlite-shm", ".db", ".env",
)
CREDENTIAL_PREFIXES = (".env.", "service-account", "service_account", "client_secret", "secrets.")


def is_credential_file(name: str) -> bool:
    low = name.lower()
    return (low in CREDENTIAL_NAMES or low.endswith(CREDENTIAL_SUFFIXES)
            or low.startswith(CREDENTIAL_PREFIXES))


@dataclass
class SupportFile:
    kind: str
    arc_rel: str
    source: Optional[Path] = None
    data: Optional[bytes] = None  # synthesized content, e.g. filtered history lines
    label: str = ""
    note: Optional[str] = None


@dataclass
class Session:
    tool: str
    session_id: str
    source: Path
    cwds: List[str] = field(default_factory=list)
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    event_count: int = 0
    events_in_range: int = 0
    records: int = 0
    malformed_lines: int = 0
    unparsed_timestamps: int = 0
    status: str = "pending"  # selected | excluded | out_of_range | unrelated | unattributable
    reason: Optional[str] = None
    match: Optional[str] = None
    touches_repo: bool = False  # some recorded cwd lies inside the repository
    # Exact bytes that were scanned for attribution; staging exports this
    # prefix only (session files may still be growing) and checks its hash.
    scanned_bytes: int = 0
    scanned_sha256: str = ""
    warnings: List[str] = field(default_factory=list)
    support: List[SupportFile] = field(default_factory=list)
    skipped_support: List[Tuple[str, str]] = field(default_factory=list)
    # tool-specific scan data
    project_dir: Optional[str] = None
    record_session_ids: set = field(default_factory=set)
    first_line_type: Optional[str] = None
    meta_id: Optional[str] = None
    backup_map: Dict[str, str] = field(default_factory=dict)

    def note_timestamp(self, value, rng: DateRange) -> None:
        ts = parse_timestamp(value)
        if ts is None:
            self.unparsed_timestamps += 1
            return
        self.event_count += 1
        if self.first_ts is None or ts < self.first_ts:
            self.first_ts = ts
        if self.last_ts is None or ts > self.last_ts:
            self.last_ts = ts
        if rng.contains(ts):
            self.events_in_range += 1

    def add_cwd(self, cwd) -> None:
        if isinstance(cwd, str) and cwd not in self.cwds:
            self.cwds.append(cwd)


@dataclass
class DiscoveryResult:
    sessions: List[Session] = field(default_factory=list)
    unrelated: Dict[str, int] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def by_status(self, status: str) -> List[Session]:
        return [s for s in self.sessions if s.status == status]


def iter_records(path: Path, session: Optional["Session"] = None) -> Iterator[Tuple[int, object]]:
    """Yield (line_no, parsed JSON or None). Opens the file read-only.

    If ``session`` is given, the number and hash of the bytes read are stored
    on it so that exactly this content can be exported later.
    """
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as fh:
        for i, raw in enumerate(fh, 1):
            digest.update(raw)
            size += len(raw)
            line = raw.rstrip(b"\r\n")
            if not line.strip():
                continue
            try:
                obj = json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                obj = None
            yield i, obj
    if session is not None:
        session.scanned_bytes = size
        session.scanned_sha256 = digest.hexdigest()


def _walk_files(root: Path) -> Iterator[Path]:
    """Regular files under root, never following symlinks."""
    if not root.is_dir() or root.is_symlink():
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            p = Path(dirpath, name)
            if p.is_file() and not p.is_symlink():
                yield p


def _attribute(s: Session, matcher: RepoMatcher, exact: bool) -> None:
    """Decide repository attribution from the recorded working directories."""
    if not s.cwds:
        s.status, s.reason = "unattributable", "no working-directory (cwd) metadata in session records"
        return
    kinds = [matcher.classify(c) for c in s.cwds]
    s.touches_repo = any(k is not None for k in kinds)
    if all(k is None for k in kinds):
        s.status = "unrelated"
        return
    if any(k is None for k in kinds):
        s.status = "excluded"
        s.reason = "working directory moves between the repository and paths outside it"
        return
    if exact and kinds[0] != "exact":
        s.status = "excluded"
        s.reason = "session started in a subdirectory of the repository (--exact is set)"
        return
    s.match = kinds[0]
    s.status = "attributed"


def _apply_dates(s: Session, rng: DateRange) -> None:
    if s.status != "attributed":
        return
    if s.event_count == 0:
        s.status, s.reason = "excluded", "no parseable event timestamps"
        return
    if s.unparsed_timestamps:
        s.warnings.append(f"{s.unparsed_timestamps} record timestamp(s) could not be parsed")
    if s.malformed_lines:
        s.warnings.append(
            f"{s.malformed_lines} malformed line(s); they are replaced by placeholder records")
    if rng.overlaps(s.first_ts, s.last_ts):
        s.status = "selected"
    else:
        s.status = "out_of_range"


def _load_filtered_lines(path: Path, key: str) -> Tuple[Dict[str, List[bytes]], int]:
    """Group the raw lines of a global JSONL index by ``key``."""
    groups: Dict[str, List[bytes]] = {}
    bad = 0
    if not path.is_file():
        return groups, bad
    with open(path, "rb") as fh:
        for line in fh:
            stripped = line.rstrip(b"\r\n")
            if not stripped.strip():
                continue
            try:
                obj = json.loads(stripped.decode("utf-8"))
            except (UnicodeDecodeError, ValueError, RecursionError):
                bad += 1
                continue
            if isinstance(obj, dict) and isinstance(obj.get(key), str):
                groups.setdefault(obj[key], []).append(stripped + b"\n")
    return groups, bad


# ---------------------------------------------------------------------------
# Codex
# ---------------------------------------------------------------------------


def codex_home(override: Optional[str] = None) -> Path:
    return Path(override or os.environ.get("CODEX_HOME") or Path.home() / ".codex")


def _scan_codex(path: Path, rng: DateRange) -> Session:
    s = Session("codex", path.stem, path)
    for line_no, obj in iter_records(path, s):
        if obj is None:
            s.malformed_lines += 1
            if line_no == 1:
                s.first_line_type = "<malformed>"
            continue
        if not isinstance(obj, dict):
            continue
        s.records += 1
        rtype = obj.get("type")
        payload = obj.get("payload")
        if s.first_line_type is None:
            s.first_line_type = rtype if isinstance(rtype, str) else "<unknown>"
            if rtype == "session_meta" and isinstance(payload, dict):
                s.meta_id = payload.get("id") if isinstance(payload.get("id"), str) else None
        if "timestamp" in obj:
            s.note_timestamp(obj.get("timestamp"), rng)
        if rtype in ("session_meta", "turn_context") and isinstance(payload, dict) and "cwd" in payload:
            s.add_cwd(payload.get("cwd"))
    return s


def discover_codex(home: Path, matcher: RepoMatcher, rng: DateRange, exact: bool,
                   result: DiscoveryResult) -> None:
    files: List[Path] = []
    for sub in ("sessions", "archived_sessions"):
        files += [p for p in _walk_files(home / sub) if p.suffix == ".jsonl"]
    history, bad_h = _load_filtered_lines(home / "history.jsonl", "session_id")
    index, bad_i = _load_filtered_lines(home / "session_index.jsonl", "id")
    if bad_h or bad_i:
        result.warnings.append(
            f"codex: ignored {bad_h + bad_i} malformed line(s) in global history/index files")

    for path in sorted(files):
        s = _scan_codex(path, rng)
        m = UUID_IN_NAME.search(path.name)
        if m:
            s.session_id = m.group(1)
        format_problem = None
        if s.first_line_type != "session_meta":
            format_problem = "unrecognized Codex format: first record is not session_meta"
        elif not s.meta_id:
            format_problem = "session_meta has no id"
        elif m and m.group(1) != s.meta_id:
            format_problem = "session_meta id does not match the file name"
        else:
            s.session_id = s.meta_id
        _attribute(s, matcher, exact)
        if format_problem and s.status != "unrelated":
            if s.touches_repo:
                s.status, s.reason = "excluded", format_problem
            else:
                # Nothing ties this file to the repository; listing it would
                # only expose other projects' session ids. Count it instead.
                result.unrelated["codex_unattributable"] = \
                    result.unrelated.get("codex_unattributable", 0) + 1
                continue
        if s.status == "unattributable":  # no cwd at all: cannot tell the project
            result.unrelated["codex_unattributable"] = \
                result.unrelated.get("codex_unattributable", 0) + 1
            continue
        _apply_dates(s, rng)
        if s.status == "unrelated":
            result.unrelated["codex"] = result.unrelated.get("codex", 0) + 1
            continue
        if s.status == "selected":
            hist = history.get(s.session_id)
            if hist:
                s.support.append(SupportFile(
                    "prompt_history", "history.jsonl", data=b"".join(hist),
                    label=display_path(home / "history.jsonl") + " (lines with this session_id)"))
            idx = index.get(s.session_id)
            if idx:
                s.support.append(SupportFile(
                    "session_index", "session_index.jsonl", data=b"".join(idx),
                    label=display_path(home / "session_index.jsonl") + " (lines with this id)"))
        result.sessions.append(s)


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


def claude_home(override: Optional[str] = None) -> Path:
    return Path(override or os.environ.get("CLAUDE_CONFIG_DIR") or Path.home() / ".claude")


def _join(base: str, rel: str) -> str:
    if is_windows_path(base):
        return ntpath.normpath(ntpath.join(base, rel))
    return posixpath.normpath(posixpath.join(base, rel))


def _basename(p: str) -> str:
    return re.split(r"[\\/]", p)[-1]


def _note_backups(s: Session, obj: dict) -> None:
    """Record backupFileName -> original absolute path from file-history records."""
    items = []
    if obj.get("type") == "file-history-snapshot" and isinstance(obj.get("snapshot"), dict):
        tracked = obj["snapshot"].get("trackedFileBackups")
        if isinstance(tracked, dict):
            items = list(tracked.items())
    elif obj.get("type") == "file-history-delta":
        items = [(obj.get("trackingPath"), obj.get("backup"))]
    for key, info in items:
        if not isinstance(key, str) or not isinstance(info, dict):
            continue
        name = info.get("backupFileName")
        if not isinstance(name, str):
            continue
        parent = info.get("realParentDir")
        if isinstance(parent, str) and (parent.startswith("/") or is_windows_path(parent)):
            original = _join(parent, _basename(key))
        elif key.startswith("/") or is_windows_path(key):
            original = key
        elif s.cwds:
            original = _join(s.cwds[0], key)
        else:
            continue
        s.backup_map[name] = original


def _scan_claude(path: Path, rng: DateRange) -> Session:
    s = Session("claude", path.stem, path, project_dir=path.parent.name)
    for _, obj in iter_records(path, s):
        if obj is None:
            s.malformed_lines += 1
            continue
        if not isinstance(obj, dict):
            continue
        s.records += 1
        s.add_cwd(obj.get("cwd"))
        if isinstance(obj.get("sessionId"), str):
            s.record_session_ids.add(obj["sessionId"])
        if "timestamp" in obj:
            s.note_timestamp(obj.get("timestamp"), rng)
        if obj.get("type") in ("file-history-snapshot", "file-history-delta"):
            _note_backups(s, obj)
    return s


def _claude_support(s: Session, home: Path, matcher: RepoMatcher, include_file_history: bool,
                    history: Dict[str, List[bytes]]) -> None:
    session_dir = s.source.parent / s.source.stem
    for p in _walk_files(session_dir):
        rel = p.relative_to(session_dir).as_posix()
        s.support.append(SupportFile(
            "session_files", "session-files/" + "/".join(safe_component(c) for c in rel.split("/")),
            source=p, label=display_path(p)))
    fh_dir = home / "file-history" / s.source.stem
    if include_file_history:
        for p in _walk_files(fh_dir):
            original = s.backup_map.get(p.name)
            label = "file-history/" + p.name
            if original is None:
                s.skipped_support.append((label, "file-history backup with no recorded original path"))
            elif matcher.classify(original) is None:
                s.skipped_support.append((label, "backup of a file outside the repository"))
            elif is_credential_file(_basename(original)):
                s.skipped_support.append((label, "backup of a credential or environment file"))
            else:
                s.support.append(SupportFile(
                    "file_history", "file-history/" + safe_component(p.name), source=p,
                    label=display_path(p), note="backup of a file inside the repository"))
    elif fh_dir.is_dir():
        s.skipped_support.append(("file-history/", "excluded by --no-file-history"))
    lines = history.get(s.session_id)
    if lines:
        s.support.append(SupportFile(
            "prompt_history", "history.jsonl", data=b"".join(lines),
            label=display_path(home / "history.jsonl") + " (lines with this sessionId)"))


def discover_claude(home: Path, matcher: RepoMatcher, rng: DateRange, exact: bool,
                    include_file_history: bool, result: DiscoveryResult) -> None:
    projects = home / "projects"
    repo_dirnames = {claude_project_dirname(f) for f in matcher.raw_forms()}
    history, bad = _load_filtered_lines(home / "history.jsonl", "sessionId")
    if bad:
        result.warnings.append(f"claude: ignored {bad} malformed line(s) in global history file")
    if not projects.is_dir():
        return
    for pdir in sorted(projects.iterdir()):
        if not pdir.is_dir() or pdir.is_symlink():
            continue
        for path in sorted(pdir.glob("*.jsonl")):
            if not path.is_file() or path.is_symlink():
                continue
            s = _scan_claude(path, rng)
            dir_matches_repo = pdir.name in repo_dirnames
            _attribute(s, matcher, exact)
            if s.status == "unattributable" and not dir_matches_repo:
                # Cannot tell which project this belongs to; report only a count
                # so unrelated project names never reach the output.
                result.unrelated["claude_unattributable"] = \
                    result.unrelated.get("claude_unattributable", 0) + 1
                continue
            if s.status == "unattributable":
                s.reason = ("no cwd metadata; the project directory name alone is not "
                            "sufficient evidence")
            elif s.status == "unrelated" and dir_matches_repo:
                s.status = "excluded"
                s.reason = ("project directory name matches the repository but the recorded "
                            "cwd does not (path-encoding collision)")
            elif s.status == "attributed" and claude_project_dirname(s.cwds[0]) != pdir.name:
                s.status = "excluded"
                s.reason = "project directory name does not match the recorded cwd"
            if s.status == "unrelated":
                result.unrelated["claude"] = result.unrelated.get("claude", 0) + 1
                continue
            if s.record_session_ids and s.record_session_ids != {s.session_id}:
                s.warnings.append("records carry a sessionId different from the file name")
            _apply_dates(s, rng)
            if s.status == "selected":
                _claude_support(s, home, matcher, include_file_history, history)
            result.sessions.append(s)


def discover(tools: List[str], matcher: RepoMatcher, rng: DateRange, exact: bool = False,
             codex_dir: Optional[str] = None, claude_dir: Optional[str] = None,
             include_file_history: bool = True) -> DiscoveryResult:
    result = DiscoveryResult()
    if "codex" in tools:
        home = codex_home(codex_dir)
        if home.is_dir():
            discover_codex(home, matcher, rng, exact, result)
        else:
            result.warnings.append(f"codex: no data directory at {display_path(home)}")
    if "claude" in tools:
        home = claude_home(claude_dir)
        if home.is_dir():
            discover_claude(home, matcher, rng, exact, include_file_history, result)
        else:
            result.warnings.append(f"claude: no data directory at {display_path(home)}")
    return result
