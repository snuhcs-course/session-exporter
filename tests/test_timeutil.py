import unittest
from datetime import date, datetime, timezone

import helpers  # noqa: F401
from session_exporter.timeutil import DateRange, parse_date, parse_timestamp


def ts(s):
    return parse_timestamp(s)


class ParseTest(unittest.TestCase):
    def test_formats(self):
        self.assertEqual(ts("2026-10-17T08:06:18.542Z"),
                         datetime(2026, 10, 17, 8, 6, 18, 542000, tzinfo=timezone.utc))
        self.assertEqual(ts("2026-10-17T17:06:18+09:00"),
                         datetime(2026, 10, 17, 8, 6, 18, tzinfo=timezone.utc))
        self.assertEqual(ts("2026-10-17T08:06:18.123456789Z").microsecond, 123456)
        self.assertIsNotNone(ts("2026-10-17T08:06:18"))  # naive -> UTC

    def test_invalid(self):
        for bad in ("yesterday", "2026-13-01T00:00:00Z", "", None, 1792242920534,
                    "2026-10-01T00:00:00+24:00", "9999-12-31T23:59:59-23:59"):
            self.assertIsNone(ts(bad))
        with self.assertRaises(ValueError):
            parse_date("2026/10/01")


class RangeTest(unittest.TestCase):
    def test_inclusive_day_boundaries_utc(self):
        r = DateRange(date(2026, 10, 1), date(2026, 10, 17), "UTC")
        self.assertTrue(r.contains(ts("2026-10-01T00:00:00.000Z")))
        self.assertTrue(r.contains(ts("2026-10-17T23:59:59.999Z")))
        self.assertFalse(r.contains(ts("2026-09-30T23:59:59.999Z")))
        self.assertFalse(r.contains(ts("2026-10-18T00:00:00.000Z")))

    def test_time_zone_boundaries(self):
        try:
            r = DateRange(date(2026, 10, 1), date(2026, 10, 1), "Asia/Seoul")
        except ValueError:
            self.skipTest("zoneinfo data not available")
        self.assertTrue(r.contains(ts("2026-09-30T15:00:00Z")))   # 10-01 00:00 KST
        self.assertFalse(r.contains(ts("2026-09-30T14:59:59Z")))  # 09-30 23:59 KST
        self.assertTrue(r.contains(ts("2026-10-01T14:59:59Z")))   # 10-01 23:59 KST
        self.assertFalse(r.contains(ts("2026-10-01T15:00:00Z")))

    def test_overlap_for_resumed_multi_day_sessions(self):
        r = DateRange(date(2026, 10, 5), date(2026, 10, 6), "UTC")
        # resumed: started long before, continued long after (no events inside)
        self.assertTrue(r.overlaps(ts("2026-09-01T10:00:00Z"), ts("2026-10-20T10:00:00Z")))
        # ends exactly at range start
        self.assertTrue(r.overlaps(ts("2026-10-01T10:00:00Z"), ts("2026-10-05T00:00:00Z")))
        # entirely before / after
        self.assertFalse(r.overlaps(ts("2026-10-01T00:00:00Z"), ts("2026-10-04T23:59:59Z")))
        self.assertFalse(r.overlaps(ts("2026-10-07T00:00:00Z"), ts("2026-10-08T00:00:00Z")))

    def test_reversed_range_rejected(self):
        with self.assertRaises(ValueError):
            DateRange(date(2026, 10, 2), date(2026, 10, 1), "UTC")


if __name__ == "__main__":
    unittest.main()
