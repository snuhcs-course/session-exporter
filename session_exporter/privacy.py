"""Sensitive-information detection and redaction.

Design rules:

* Findings never carry the matched text. Only the detector name, category and
  location (file, line, JSON path) are recorded, so nothing sensitive can leak
  into logs, previews, the manifest or error messages.
* JSONL files are processed record by record: each line is parsed, every
  string (keys included) is redacted, and the record is re-serialized, so the
  output is always valid JSONL.
* Fail closed: a line that cannot be parsed or redacted is replaced by a
  small placeholder record; a non-JSONL file that cannot be processed is
  excluded entirely. Raw, unprocessed content is never copied through.
"""

from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Tuple

from .paths import claude_project_dirname

PLACEHOLDER_PREFIX = "[REDACTED"
OMITTED_RECORD_TYPE = "session_exporter.omitted_line"
MAX_PASSES = 3

# ---------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------

_PLACEHOLDER_WORDS = {
    "none", "null", "nil", "true", "false", "undefined", "string", "str",
    "required", "optional", "password", "passwd", "secret", "token", "example",
    "changeme", "your_password", "yourpassword", "your-password", "xxxx",
    "xxxxxx", "xxxxxxxx", "redacted", "hidden", "masked",
}
_DOTTED_IDENT = re.compile(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+[(\[]?")


def _not_placeholder(v: str) -> bool:
    low = v.strip("'\"").lower()
    if not low or low.startswith("[redacted"):
        return False
    if low in _PLACEHOLDER_WORDS:
        return False
    if v[0] in "$%{<(" or v.endswith(("(", "[")):
        return False  # ${VAR}, %VAR%, {{tmpl}}, <password>, func(
    if _DOTTED_IDENT.fullmatch(v):
        return False  # self.password, os.environ.get(
    if set(v) <= set("*xX•.-_"):
        return False
    return True


def _letters_and_digits(v: str) -> bool:
    return any(c.isalpha() for c in v) and any(c.isdigit() for c in v)


def _generic_secret_ok(v: str) -> bool:
    return _not_placeholder(v) and _letters_and_digits(v)


_EMAIL_ALLOW_DOMAINS = {"example.com", "example.org", "example.net"}
_EMAIL_ALLOW_ADDRESSES = {"noreply@anthropic.com"}


def _email_ok(v: str) -> bool:
    low = v.lower()
    if low in _EMAIL_ALLOW_ADDRESSES or low.startswith("git@"):  # SSH remotes
        return False
    domain = low.rsplit("@", 1)[-1]
    if domain in _EMAIL_ALLOW_DOMAINS or domain.endswith((".example", ".test", ".invalid", ".localhost")):
        return False
    return True


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def _card_ok(v: str) -> bool:
    d = re.sub(r"[ -]", "", v)
    if not 13 <= len(d) <= 19:
        return False
    known = (
        d[0] == "4"
        or 51 <= int(d[:2]) <= 55
        or 2221 <= int(d[:4]) <= 2720
        or d[:2] in ("34", "37")
        or d[:4] == "6011" or d[:2] == "65"
        or 3528 <= int(d[:4]) <= 3589
    )
    return known and _luhn(d)


_HOME_NAMES_ALLOWED = {"shared", "public", "default", "all users", "~"}


def _username_ok(v: str) -> bool:
    return not v.startswith(PLACEHOLDER_PREFIX) and v.lower() not in _HOME_NAMES_ALLOWED


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------


@dataclass
class Detector:
    name: str
    category: str  # "secret", "pii" or "path"
    pattern: "re.Pattern[str]"
    group: int = 0
    validator: Optional[Callable[[str], bool]] = None
    replacement: Optional[str] = None
    # Cheap pre-check: the regex only runs if one of these substrings occurs
    # (in the lower-cased text when hints_ci is set). Purely an optimization.
    hints: Tuple[str, ...] = ()
    hints_ci: bool = False

    def applies(self, text: str, lower: str) -> bool:
        if not self.hints:
            return True
        hay = lower if self.hints_ci else text
        return any(h in hay for h in self.hints)

    def _accept(self, value: Optional[str]) -> bool:
        if not value or PLACEHOLDER_PREFIX in value:
            return False
        return self.validator is None or self.validator(value)

    def _spans(self, text: str, view: str):
        for m in self.pattern.finditer(view):
            s, e = m.span(self.group)
            if s < 0 or PLACEHOLDER_PREFIX in text[s:e]:
                continue
            if self._accept(m.group(self.group)):
                yield s, e

    def sub(self, text: str, view: Optional[str] = None) -> Tuple[str, int]:
        """Replace matches. Matching runs on ``view`` (same length as text,
        e.g. with escape sequences blanked); replacement happens in ``text``."""
        view = text if view is None else view
        repl_text = self.replacement or f"[REDACTED:{self.name}]"
        out, pos, count = [], 0, 0
        for s, e in self._spans(text, view):
            out.append(text[pos:s])
            out.append(repl_text)
            pos = e
            count += 1
        if not count:
            return text, 0
        out.append(text[pos:])
        return "".join(out), count

    def count(self, text: str, view: Optional[str] = None) -> int:
        return sum(1 for _ in self._spans(text, text if view is None else view))


def _d(name, category, pattern, hints=(), ci=False, **kw) -> Detector:
    return Detector(name, category, pattern, hints=tuple(hints), hints_ci=ci, **kw)


def _secret_detectors() -> List[Detector]:
    I = re.IGNORECASE
    return [
        _d("private_key", "secret", re.compile(
            r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"
            r"(?:[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----|[\s\S]*\Z)"),
           hints=("PRIVATE KEY",)),
        _d("anthropic_api_key", "secret", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
           hints=("sk-ant-",)),
        _d("openai_api_key", "secret",
           re.compile(r"\bsk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
           hints=("sk-",), validator=_letters_and_digits),
        _d("aws_access_key_id", "secret",
           re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b"),
           hints=("AKIA", "ASIA", "AGPA", "AIDA", "AROA", "ANPA")),
        _d("aws_secret_access_key", "secret", re.compile(
            r"aws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])", I),
           hints=("secret",), ci=True, group=1),
        _d("github_token", "secret",
           re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
           hints=("ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_")),
        _d("gitlab_token", "secret", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"), hints=("glpat-",)),
        _d("slack_token", "secret", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}"), hints=("xox",)),
        _d("slack_webhook", "secret",
           re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+"),
           hints=("hooks.slack.com",)),
        _d("google_api_key", "secret", re.compile(r"\bAIza[0-9A-Za-z_-]{35}"), hints=("AIza",)),
        _d("stripe_key", "secret", re.compile(r"\b[rs]k_(?:live|test)_[0-9A-Za-z]{16,}"),
           hints=("_live_", "_test_")),
        _d("huggingface_token", "secret", re.compile(r"\bhf_[A-Za-z0-9]{30,}"), hints=("hf_",)),
        _d("npm_token", "secret", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), hints=("npm_",)),
        _d("jwt", "secret",
           re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
           hints=("eyJ",)),
        _d("bearer_token", "secret",
           re.compile(r"\b(?:bearer|token)\s+([A-Za-z0-9._~+/=-]{20,})", I),
           hints=("bearer", "token"), ci=True, group=1, validator=_generic_secret_ok),
        _d("basic_auth", "secret", re.compile(
            r"authorization[\"']?\s*[:=]\s*[\"']?basic\s+([A-Za-z0-9+/]{8,}={0,2})", I),
           hints=("authorization",), ci=True, group=1),
        _d("url_credentials", "secret", re.compile(
            r"\b[A-Za-z][A-Za-z0-9+.-]{0,30}://[^/\s:@\"'<>]{1,256}:([^/\s@\"'<>]{1,256})@"),
           hints=("://",), group=1, validator=_not_placeholder),
        _d("password_assignment", "secret", re.compile(
            r"(?:\b[A-Z0-9_]{0,40}(?:PASSWORD|PASSWD|PASSPHRASE)\b|\b(?:[A-Z0-9]{1,20}_){0,5}(?:PASS|PWD)\b"
            r"|(?<![A-Za-z])(?i:password|passwd|passphrase|pwd)(?![A-Za-z])|비밀번호|패스워드)"
            r"[\"']?\s*[:=]\s*[\"']?([^\s\"'`,;]{4,})"),
           hints=("pass", "pwd", "비밀번호", "패스워드"), ci=True, group=1,
           validator=_not_placeholder),
        # Passwords given as command-line flags: mysql -p'pw', sshpass -p pw
        _d("password_assignment", "secret", re.compile(
            r"\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n]{0,200}?\s-p['\"]?([^\s'\"]{4,})"),
           hints=("mysql", "mariadb"), group=1, validator=_not_placeholder),
        _d("password_assignment", "secret", re.compile(
            r"\bsshpass\s+-p\s*['\"]?([^\s'\"]{4,})"),
           hints=("sshpass",), group=1, validator=_not_placeholder),
        _d("secret_assignment", "secret", re.compile(
            r"(?:api[_-]?key|apikey|secret|token|access[_-]?key|private[_-]?key"
            r"|client[_-]?secret|credential)s?\b[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-./+=~]{12,})", I),
           hints=("key", "secret", "token", "credential"), ci=True, group=1,
           validator=_generic_secret_ok),
    ]


def _pii_detectors() -> List[Detector]:
    return [
        _d("email", "pii",
           re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,24}\b"),
           hints=("@",), validator=_email_ok),
        _d("kr_resident_number", "pii", re.compile(
            r"(?<![\w-])\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])-[1-4]\d{6}(?![\w-])"),
           hints=("-",)),
        _d("phone_number", "pii", re.compile(
            r"(?<![\w-])(?:(?:\+82[- ]?1[016789]|01[016789])[- .]?\d{3,4}[- .]?\d{4}"
            r"|(?:\+1[ -]?)?\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4})(?![\w-])")),
        # Real card groupings only (4-4-4-4[-n], Amex 4-6-5, or contiguous) to
        # avoid matching arbitrary digit runs in logs; then prefix + Luhn check.
        _d("credit_card", "pii", re.compile(
            r"(?<![\w-])(?:\d{4}([ -])\d{4}\1\d{4}\1\d{1,7}|\d{4}([ -])\d{6}\2\d{5}|\d{13,19})"
            r"(?![\w-])"),
           validator=_card_ok),
    ]


def _path_detectors(home: Path) -> List[Detector]:
    detectors = []
    home_str = str(home)
    variants = []
    if re.match(r"^[A-Za-z]:[\\/]", home_str):
        parts = re.split(r"[\\/]+", home_str.strip("\\/"))
        variants.append(r"[\\/]{1,2}".join(re.escape(p) for p in parts) + r"(?![A-Za-z0-9_.-])")
    elif home_str not in ("", "/"):
        variants.append(re.escape(home_str.rstrip("/")) + r"(?![A-Za-z0-9_.-])")
    encoded = claude_project_dirname(home_str)
    if encoded.strip("-"):
        variants.append(re.escape(encoded) + r"(?![A-Za-z0-9])")
    if variants:
        flags = re.IGNORECASE if re.match(r"^[A-Za-z]:", home_str) else 0
        detectors.append(_d("home_directory", "path", re.compile("|".join(variants), flags),
                            replacement="~"))
    detectors.append(_d("user_home", "path", re.compile(
        r"(?:(?<![\w./-])/(?:Users|home)/|\b[A-Za-z]:[\\/]{1,2}(?i:users)[\\/]{1,2})"
        r"([^\\/\s\"'<>|:*?`]+)"),
        hints=("users", "/home/"), ci=True, group=1, validator=_username_ok,
        replacement="[REDACTED:username]"))
    return detectors


# Key-based rules, applied while walking parsed JSON objects.
_SENSITIVE_KEY_SUFFIXES = (
    "password", "passwd", "passphrase", "secret", "apikey", "accesstoken",
    "refreshtoken", "authtoken", "idtoken", "sessiontoken", "privatekey",
    "secretkey", "accesskey", "clientsecret", "credential", "credentials", "token", "secrets",
)
# Account identifiers verified in real session files (Codex session_meta and
# Claude Code records), plus a generic "email" key.
IDENTITY_KEYS = {
    "creator_user_id", "creator_account_id", "userEmail", "organizationUuid",
    "user_identity", "email",
}


_ENV_PASS_KEY = re.compile(r"^(?:[A-Z0-9_]*_)?PASS$")


# Plural forms only apply to non-numeric values, so usage counters such as
# "input_tokens": 1234 stay intact.
_PLURAL_KEY_SUFFIXES = ("tokens", "passwords", "apikeys", "secretkeys", "accesskeys",
                        "privatekeys")


def is_sensitive_key(key: str, value=None) -> bool:
    k = re.sub(r"[^a-z0-9]", "", key.lower())
    if k == "pwd" or k.endswith(_SENSITIVE_KEY_SUFFIXES) or k.endswith("authorization") \
            or _ENV_PASS_KEY.match(key) or "비밀번호" in key or "패스워드" in key:
        return True
    return isinstance(value, (str, list, dict)) and k.endswith(_PLURAL_KEY_SUFFIXES)


# Escape sequences that can glue onto a secret and defeat word boundaries:
# ANSI colour codes (real or written as \u001b / \x1b / \033 / \e) and
# backslash escapes such as \n or \" inside text (e.g. JSON inside a string).
_VIEW_BLANK = re.compile(
    r"(?:\x1b|\\+u001[bB]|\\+x1[bB]|\\+033|\\+e)\[[0-9;?]*[A-Za-z]"
    r"|\\+(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)|\x1b", re.DOTALL)  # \\+: nested escaping


def escape_blanked_view(text: str) -> str:
    """Same-length copy of text with escape sequences replaced by spaces."""
    return _VIEW_BLANK.sub(lambda m: " " * len(m.group(0)), text)


def _needs_view(text: str) -> bool:
    return "\\" in text or "\x1b" in text


CATEGORIES = {"sensitive_field": "secret", "account_identifier": "pii", "custom_term": "pii"}


# ---------------------------------------------------------------------------
# Redactor
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    file: str
    detector: str
    category: str
    line: Optional[int] = None
    json_path: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"file": self.file, "detector": self.detector, "category": self.category}
        if self.line is not None:
            d["line"] = self.line
        if self.json_path is not None:
            d["json_path"] = self.json_path
        return d


class RedactionError(Exception):
    """Raised when content cannot be redacted safely. Never carries content."""


class Redactor:
    def __init__(self, extra_terms: Iterable[str] = (), redact_paths: bool = True,
                 home: Optional[Path] = None):
        self.detectors: List[Detector] = _secret_detectors() + _pii_detectors()
        if redact_paths:
            self.detectors += _path_detectors(home or Path.home())
        for term in extra_terms:
            if term and term.strip():
                self.detectors.append(_d(
                    "custom_term", "pii", re.compile(re.escape(term.strip()), re.IGNORECASE),
                    hints=(term.strip().lower(),), ci=True))
        for d in self.detectors:
            CATEGORIES.setdefault(d.name, d.category)

    def detector_names(self) -> List[str]:
        names = [d.name for d in self.detectors] + ["sensitive_field", "account_identifier"]
        return sorted(set(names))

    # -- plain text -------------------------------------------------------
    def redact_text(self, text: str) -> Tuple[str, List[str]]:
        hits: List[str] = []
        lower = text.lower()
        for d in self.detectors:
            if not d.applies(text, lower):
                continue
            text, n = d.sub(text)
            if n:
                hits.extend([d.name] * n)
                lower = text.lower()
        if _needs_view(text):
            view = escape_blanked_view(text)
            lower = view.lower()
            for d in self.detectors:
                if not d.applies(view, lower):
                    continue
                text, n = d.sub(text, view)
                if n:
                    hits.extend([d.name] * n)
                    view = escape_blanked_view(text)
                    lower = view.lower()
        return text, hits

    def scan_text(self, text: str) -> List[str]:
        hits: List[str] = []
        views = [text] + ([escape_blanked_view(text)] if _needs_view(text) else [])
        for view in views:
            lower = view.lower()
            for d in self.detectors:
                if d.applies(view, lower):
                    hits.extend([d.name] * d.count(text, view))
        return hits

    def redact_text_fully(self, text: str) -> Tuple[str, List[str]]:
        total: List[str] = []
        for _ in range(MAX_PASSES):
            text, hits = self.redact_text(text)
            if not hits:
                return text, total
            total.extend(hits)
        if self.scan_text(text):
            raise RedactionError("redaction did not converge")
        return text, total

    # -- parsed JSON ------------------------------------------------------
    def redact_obj(self, obj) -> Tuple[object, List[Tuple[str, str]]]:
        """Redact every string (and key) in a parsed JSON value.

        Returns the new value and a list of (json_path, detector) hits.
        """
        hits: List[Tuple[str, str]] = []

        def rec(o, path):
            if isinstance(o, str):
                new, names = self.redact_text(o)
                hits.extend((path, n) for n in names)
                return new
            if isinstance(o, list):
                return [rec(x, f"{path}[{i}]") for i, x in enumerate(o)]
            if isinstance(o, dict):
                out = {}
                # {"name": "API_KEY", "value": "..."} style environment lists
                pair_name = next((o[n] for n in ("name", "key") if isinstance(o.get(n), str)), None)
                pair_secret = pair_name is not None and is_sensitive_key(pair_name)
                for k, v in o.items():
                    new_k, knames = self.redact_text(k)
                    hits.extend((path + ".<key>", n) for n in knames)
                    child = path + _path_segment(k, bool(knames))
                    if _has_content(v) and (is_sensitive_key(k, v) or (pair_secret and k == "value")):
                        new_v = "[REDACTED:sensitive_field]"
                        hits.append((child, "sensitive_field"))
                    elif _has_content(v) and k in IDENTITY_KEYS:
                        new_v = "[REDACTED:account_identifier]"
                        hits.append((child, "account_identifier"))
                    else:
                        new_v = rec(v, child)
                    while new_k in out:
                        new_k += "_"
                    out[new_k] = new_v
                return out
            if isinstance(o, int) and not isinstance(o, bool) and abs(o) >= 10 ** 8:
                # Long integers may be phone or card numbers stored as numbers.
                _, names = self.redact_text(str(o))
                if names:
                    hits.extend((path, n) for n in names)
                    return f"[REDACTED:{names[0]}]"
            return o

        return rec(obj, "$"), hits


def _has_content(v) -> bool:
    """True for values worth redacting under a sensitive key."""
    if v is None or isinstance(v, bool):
        return False
    if isinstance(v, str):
        return bool(v.strip()) and not v.startswith(PLACEHOLDER_PREFIX)
    if isinstance(v, (list, dict)):
        return bool(v)
    return True  # numbers


_SIMPLE_KEY = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


def _path_segment(key: str, key_was_redacted: bool) -> str:
    if key_was_redacted or not _SIMPLE_KEY.match(key):
        return ".<key>"
    return "." + key


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------


@dataclass
class FileResult:
    data: Optional[bytes]  # None means the file is excluded (fail closed)
    counts: Counter = field(default_factory=Counter)
    locations: List[Finding] = field(default_factory=list)
    omitted_lines: List[Tuple[int, str]] = field(default_factory=list)
    blank_lines: int = 0
    excluded_reason: Optional[str] = None

    def add(self, finding: Finding) -> None:
        self.counts[finding.detector] += 1
        if finding.category != "path":  # home-path hits are too common to list
            self.locations.append(finding)


def _reject_constant(name):
    raise ValueError("non-standard JSON constant")


class DuplicateKeyError(ValueError):
    """A JSON object repeats a key. Parsers disagree on which copy wins, and
    any renaming would dodge key-based rules, so such records are omitted."""


def _pairs_no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise DuplicateKeyError("duplicate key")
        out[k] = v
    return out


def _loads(text: str):
    return json.loads(text, parse_constant=_reject_constant,
                      object_pairs_hook=_pairs_no_duplicates)


def _dumps(obj, indent=None) -> str:
    seps = (",", ":") if indent is None else (",", ": ")
    text = json.dumps(obj, ensure_ascii=False, separators=seps, indent=indent)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:  # lone surrogates: escape them instead
        text = json.dumps(obj, ensure_ascii=True, separators=seps, indent=indent)
    return text


def omitted_record(line_no: int, reason: str) -> str:
    return _dumps({"type": OMITTED_RECORD_TYPE, "original_line": line_no, "reason": reason})


def _redact_json_value(obj, original_text: Optional[str], redactor: Redactor,
                       dump: Callable[[object], str]) -> Tuple[str, List[Tuple[str, str]]]:
    """Redact a parsed JSON value and return its serialized text plus hits.

    ``original_text`` is kept byte-for-byte when nothing was redacted; pass
    None to force re-serialization.
    """
    all_hits: List[Tuple[str, str]] = []
    for _ in range(MAX_PASSES):
        obj, hits = redactor.redact_obj(obj)
        if not hits:
            break
        all_hits.extend(hits)
    else:
        if redactor.redact_obj(obj)[1]:
            raise RedactionError("redaction did not converge")
    text = dump(obj) if (all_hits or original_text is None) else original_text
    # Belt and braces: scan a structural view (keys, values and JSON
    # punctuation, with string contents unescaped) for matches that span
    # several JSON values, e.g. a key and the next value. Such a match cannot
    # be redacted inside one string, so fail closed and drop the record.
    if redactor.scan_text(_structural_view(obj)):
        raise RedactionError("match spans JSON structure")
    return text, all_hits


def _structural_view(o) -> str:
    if isinstance(o, str):
        return '"' + escape_blanked_view(o) + '"'
    if isinstance(o, dict):
        return "{" + ",".join(_structural_view(k) + ":" + _structural_view(v)
                              for k, v in o.items()) + "}"
    if isinstance(o, list):
        return "[" + ",".join(_structural_view(x) for x in o) + "]"
    return json.dumps(o)


def process_jsonl(raw: bytes, arc: str, redactor: Redactor) -> FileResult:
    result = FileResult(data=None)
    lines = raw.split(b"\n")
    complete = raw.endswith(b"\n")
    if complete:
        lines = lines[:-1]
    out: List[str] = []
    for idx, line in enumerate(lines, 1):
        last_incomplete = idx == len(lines) and not complete
        if line.endswith(b"\r"):
            line = line[:-1]
        if not line.strip():
            result.blank_lines += 1
            continue
        try:
            text = line.decode("utf-8")
        except UnicodeDecodeError:
            reason = "incomplete_trailing_line" if last_incomplete else "invalid_utf8"
            result.omitted_lines.append((idx, reason))
            out.append(omitted_record(idx, reason))
            continue
        try:
            obj = _loads(text)
        except DuplicateKeyError:
            result.omitted_lines.append((idx, "duplicate_keys"))
            out.append(omitted_record(idx, "duplicate_keys"))
            continue
        except (ValueError, RecursionError):
            reason = "incomplete_trailing_line" if last_incomplete else "malformed_json"
            result.omitted_lines.append((idx, reason))
            out.append(omitted_record(idx, reason))
            continue
        try:
            new_text, hits = _redact_json_value(obj, text, redactor, _dumps)
            new_text.encode("utf-8")
        except Exception:
            result.omitted_lines.append((idx, "redaction_error"))
            out.append(omitted_record(idx, "redaction_error"))
            continue
        for path, name in hits:
            result.add(Finding(arc, name, CATEGORIES.get(name, "secret"), idx, path))
        out.append(new_text)
    result.data = ("\n".join(out) + "\n").encode("utf-8") if out else b""
    return result


def process_json(raw: bytes, arc: str, redactor: Redactor) -> FileResult:
    try:
        text = raw.decode("utf-8")
        new_text, hits = _redact_json_value(_loads(text), text, redactor,
                                            lambda o: _dumps(o, indent=2))
        data = new_text.encode("utf-8")
    except Exception:
        return FileResult(data=None, excluded_reason="JSON file could not be parsed or redacted")
    result = FileResult(data=data)
    for path, name in hits:
        result.add(Finding(arc, name, CATEGORIES.get(name, "secret"), None, path))
    return result


def looks_binary(raw: bytes) -> bool:
    return b"\x00" in raw[:8192]


def process_text(raw: bytes, arc: str, redactor: Redactor) -> FileResult:
    if looks_binary(raw):
        return FileResult(data=None, excluded_reason="binary file cannot be scanned")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return FileResult(data=None, excluded_reason="non-UTF-8 file cannot be scanned")
    try:
        new_text, hits = redactor.redact_text_fully(text)
        data = new_text.encode("utf-8")
    except Exception:
        return FileResult(data=None, excluded_reason="text could not be redacted")
    result = FileResult(data=data)
    for name in hits:
        result.add(Finding(arc, name, CATEGORIES.get(name, "secret")))
    return result


def process_file(raw: bytes, arc: str, redactor: Redactor) -> FileResult:
    lower = arc.lower()
    if lower.endswith(".jsonl"):
        return process_jsonl(raw, arc, redactor)
    if lower.endswith(".json"):
        return process_json(raw, arc, redactor)
    return process_text(raw, arc, redactor)


def rescan_file(data: bytes, arc: str, redactor: Redactor) -> List[str]:
    """Final verification of an already-redacted file.

    Processing must be a no-op: no findings, no omitted lines, identical
    bytes. Returns a list of content-free problem descriptions.
    """
    problems: List[str] = []
    try:
        res = process_file(data, arc, redactor)
    except Exception as exc:  # pragma: no cover - defensive
        return [f"{arc}: re-scan failed ({type(exc).__name__})"]
    if res.data is None:
        problems.append(f"{arc}: {res.excluded_reason}")
        return problems
    if res.counts:
        kinds = ", ".join(f"{k} x{v}" for k, v in sorted(res.counts.items()))
        problems.append(f"{arc}: unredacted matches remain ({kinds})")
    if res.omitted_lines:
        problems.append(f"{arc}: {len(res.omitted_lines)} line(s) are not valid JSON")
    if res.blank_lines:
        problems.append(f"{arc}: contains blank lines")
    if res.data != data and not res.counts:
        problems.append(f"{arc}: content is not in normalized form")
    return problems
