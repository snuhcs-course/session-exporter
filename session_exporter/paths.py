"""Path normalization and repository matching.

Paths recorded in session files may come from macOS, Linux or Windows, so they
are parsed by their own syntax (not the host's) and compared component by
component. Substring matching is never used: ``/work/repo`` does not match
``/work/repo-old``.
"""

from __future__ import annotations

import ntpath
import os
import posixpath
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from typing import Optional

_WIN_ABS = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\)")
_WIN_EXTENDED = re.compile(r"^\\\\\?\\(UNC\\)?", re.IGNORECASE)
_HOST_IS_WINDOWS = os.name == "nt"


@dataclass(frozen=True)
class NormPath:
    flavor: str  # "posix" or "windows"
    anchor: str
    parts: tuple

    def is_within(self, other: "NormPath") -> bool:
        """True if self equals ``other`` or lies below it."""
        return (
            self.flavor == other.flavor
            and self.anchor == other.anchor
            and len(self.parts) >= len(other.parts)
            and self.parts[: len(other.parts)] == other.parts
        )


def is_windows_path(raw: str) -> bool:
    return bool(_WIN_ABS.match(raw))


def is_absolute_any(raw: str) -> bool:
    return isinstance(raw, str) and (raw.startswith("/") or is_windows_path(raw))


def _nfc(s: str) -> str:
    # macOS file systems may store decomposed (NFD) names; session files
    # usually record composed (NFC) text. Compare in NFC.
    return unicodedata.normalize("NFC", s)


def normalize(raw: str, case_insensitive: bool) -> Optional[NormPath]:
    """Normalize an absolute path string; returns None if not absolute."""
    if not isinstance(raw, str) or not raw or "\x00" in raw:
        return None
    s = _nfc(raw)
    if is_windows_path(s):
        m = _WIN_EXTENDED.match(s)
        if m:
            s = ("\\\\" if m.group(1) else "") + s[m.end():]
        s = ntpath.normpath(s.replace("/", "\\"))
        p = PureWindowsPath(s)
        # Windows paths are always compared case-insensitively.
        anchor = p.anchor.replace("/", "\\").casefold()
        parts = tuple(x.casefold() for x in p.parts[1:])
        return NormPath("windows", anchor, parts)
    if s.startswith("/"):
        s = posixpath.normpath(s)
        parts = tuple(x for x in s.split("/") if x)
        if case_insensitive:
            parts = tuple(x.casefold() for x in parts)
        return NormPath("posix", "/", parts)
    return None


def _host_style(raw: str) -> bool:
    """True if ``raw`` uses the host OS path syntax (so it can be stat'ed)."""
    return is_windows_path(raw) if _HOST_IS_WINDOWS else raw.startswith("/")


def _realpath(raw: str) -> Optional[str]:
    if not _host_style(raw):
        return None
    try:
        if not os.path.exists(raw):
            return None
        return os.path.realpath(raw)
    except (OSError, ValueError):
        return None


def probe_case_insensitive(path: str) -> bool:
    """Detect whether the file system holding ``path`` ignores case."""
    if _HOST_IS_WINDOWS:
        return True
    p = Path(path)
    while True:
        name = p.name
        if name and name.swapcase() != name:
            try:
                if p.exists():
                    alt = p.with_name(name.swapcase())
                    return alt.exists() and os.path.samefile(p, alt)
            except OSError:
                return False
        if p.parent == p:
            return False
        p = p.parent


class RepoMatcher:
    """Decides whether a recorded working directory belongs to the repo."""

    def __init__(self, repo: str, case_mode: str = "auto"):
        if not is_absolute_any(repo):
            raise ValueError("repository path must be absolute")
        if case_mode == "auto":
            self.case_insensitive = probe_case_insensitive(repo)
        else:
            self.case_insensitive = case_mode == "insensitive"
        self.raw = repo
        real = _realpath(repo)
        self.exists = real is not None
        # Paths that exist on this machine are compared by their resolved
        # (symlink-free) location; recorded paths that no longer exist can
        # only be compared textually, against both spellings of the repo.
        self.real_forms = {n for n in [normalize(real, self.case_insensitive)] if n} if real else set()
        given = normalize(repo, self.case_insensitive)
        self.forms = self.real_forms | ({given} if given else set())
        if not self.forms:
            raise ValueError("repository path could not be normalized")
        self._cache = {}

    def raw_forms(self) -> list:
        forms = [self.raw]
        real = _realpath(self.raw)
        if real and real != self.raw:
            forms.append(real)
        return forms

    def classify(self, cwd: str) -> Optional[str]:
        """Return "exact", "subdirectory" or None (outside the repo)."""
        if cwd in self._cache:
            return self._cache[cwd]
        real = _realpath(cwd)
        if real is not None and self.real_forms:
            # The directory exists here: its real location decides, so a
            # symlink inside the repo pointing elsewhere does not count.
            c, repo_forms = normalize(real, self.case_insensitive), self.real_forms
        else:
            c, repo_forms = normalize(cwd, self.case_insensitive), self.forms
        result = None
        if c is not None:
            for r in repo_forms:
                if c == r:
                    result = "exact"
                    break
                if c.is_within(r):
                    result = "subdirectory"
        self._cache[cwd] = result
        return result


def claude_project_dirname(cwd: str) -> str:
    """Encode a cwd the way Claude Code names ``~/.claude/projects/<dir>``.

    Verified against local data: every non-alphanumeric character becomes "-".
    """
    return re.sub(r"[^A-Za-z0-9]", "-", cwd)


def display_path(path) -> str:
    """Render a local path with the home directory shown as ``~``."""
    s = str(path)
    home = str(Path.home())
    if s == home:
        return "~"
    for sep in ("/", "\\"):
        if s.startswith(home + sep):
            return "~" + sep + s[len(home) + 1:]
    return s


_SAFE_COMPONENT = re.compile(r"[^A-Za-z0-9._@=+-]")
_WINDOWS_RESERVED = re.compile(r"^(?:CON|PRN|AUX|NUL|COM[0-9]|LPT[0-9])(?:\..*)?$", re.IGNORECASE)


def safe_component(name: str) -> str:
    """Make one archive path component safe on every OS: no separators, no
    '..', no Windows reserved device names, no trailing dots."""
    cleaned = _SAFE_COMPONENT.sub("_", name)
    if len(cleaned) > 120:  # shorten the stem, keep a (short) extension
        stem, dot, ext = cleaned.rpartition(".")
        if dot and stem and len(ext) <= 16:
            cleaned = stem[: 119 - len(ext)] + "." + ext
        else:
            cleaned = cleaned[:120]
    if cleaned.endswith("."):
        cleaned = cleaned.rstrip(".") + "_"
    if not cleaned or cleaned.startswith("..") or _WINDOWS_RESERVED.match(cleaned):
        cleaned = "_" + cleaned
    return cleaned
