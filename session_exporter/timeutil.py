"""Timestamp parsing and date-range handling."""

from __future__ import annotations

import re
from datetime import date, datetime, timedelta, timezone
from typing import Optional, Tuple

_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})"
    r"(?:\.(\d{1,9}))?(Z|[+-]\d{2}:?\d{2})?$"
)


def parse_timestamp(value) -> Optional[datetime]:
    """Parse an ISO-8601 event timestamp into an aware UTC datetime.

    Both Codex and Claude Code record ``YYYY-MM-DDTHH:MM:SS.fffZ``. A missing
    offset is treated as UTC. Anything else returns None.
    """
    if not isinstance(value, str):
        return None
    m = _ISO.match(value.strip())
    if not m:
        return None
    y, mo, d, h, mi, s, frac, off = m.groups()
    micro = int((frac or "0").ljust(6, "0")[:6])
    try:
        if off in (None, "Z"):
            tz = timezone.utc
        else:
            sign = 1 if off[0] == "+" else -1
            digits = off[1:].replace(":", "")
            tz = timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))
        dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), micro, tzinfo=tz)
        return dt.astimezone(timezone.utc)
    except (ValueError, OverflowError):
        return None


def parse_date(text: str) -> date:
    try:
        return datetime.strptime(text, "%Y-%m-%d").date()
    except ValueError:
        raise ValueError(f"invalid date {text!r}; expected YYYY-MM-DD") from None


def resolve_timezone(name: str):
    """Return a tzinfo, or None for the system local time zone."""
    if name in ("local", ""):
        return None
    if name.upper() == "UTC":
        return timezone.utc
    try:
        from zoneinfo import ZoneInfo  # Python 3.9+
        return ZoneInfo(name)
    except Exception:
        raise ValueError(
            f"unknown time zone {name!r} (on Windows you may need: pip install tzdata)"
        ) from None


def _midnight(d: date, tz) -> datetime:
    naive = datetime(d.year, d.month, d.day)
    if tz is None:
        # astimezone() on a naive datetime applies the local rules for that
        # specific date, so DST transitions are handled correctly.
        return naive.astimezone().astimezone(timezone.utc)
    return naive.replace(tzinfo=tz).astimezone(timezone.utc)


class DateRange:
    """Inclusive calendar-day range [from, to] in a given time zone."""

    def __init__(self, start: date, end: date, tz_name: str = "local"):
        if end < start:
            raise ValueError("--from must not be after --to")
        self.start_date = start
        self.end_date = end
        self.tz_name = tz_name
        tz = resolve_timezone(tz_name)
        self.start = _midnight(start, tz)
        self.end_exclusive = _midnight(end + timedelta(days=1), tz)

    def contains(self, ts: datetime) -> bool:
        return self.start <= ts < self.end_exclusive

    def overlaps(self, first: datetime, last: datetime) -> bool:
        return first < self.end_exclusive and last >= self.start

    def describe(self) -> dict:
        return {
            "from": self.start_date.isoformat(),
            "to": self.end_date.isoformat(),
            "timezone": self.tz_name,
            "start_utc": iso(self.start),
            "end_utc_exclusive": iso(self.end_exclusive),
        }


def iso(ts: Optional[datetime]) -> Optional[str]:
    if ts is None:
        return None
    return ts.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def span(timestamps) -> Tuple[Optional[datetime], Optional[datetime]]:
    ts = list(timestamps)
    return (min(ts), max(ts)) if ts else (None, None)
