# AGENT.md — notes for coding agents working on this repository

## What this is
A dependency-free Python (>= 3.9) CLI that exports Codex CLI / Claude Code
session histories for one repository and date range into a redacted ZIP.
User docs: `README.md`. Entry points: `export_sessions.py` (no install) and
`session-exporter` (console script via `pyproject.toml`).

## Layout
| File | Responsibility |
| --- | --- |
| `session_exporter/cli.py` | argparse, console output, review prompt, exit codes |
| `session_exporter/discovery.py` | find session files, scan metadata, attribute to repo, collect supporting files |
| `session_exporter/paths.py` | path normalization (POSIX/Windows), `RepoMatcher`, Claude dir-name encoding |
| `session_exporter/timeutil.py` | ISO timestamp parsing, inclusive `DateRange` in a time zone |
| `session_exporter/privacy.py` | detectors, `Redactor`, JSONL/JSON/text processing, `rescan_file` |
| `session_exporter/exporter.py` | staging, final re-scan, manifest, ZIP writing + verification |
| `tests/helpers.py` | synthetic fixture builders mirroring the real record shapes |

## Invariants — do not break
1. **Read-only originals.** Session files are only opened with `open(..., "rb")` /
   `read_bytes()`. Never write under the Codex/Claude data dirs (the CLI also
   refuses an `--output` inside them).
2. **No sensitive values in output.** `Finding` stores detector/category/file/
   line/JSON path only. Error messages use exception *class names*, never
   `str(exc)` of content-bearing errors. JSON paths replace unusual or redacted
   keys with `<key>`.
3. **Fail closed.** Unparseable/unredactable JSONL lines → placeholder record
   (`session_exporter.omitted_line`). Unscannable files (binary, non-UTF-8,
   invalid JSON) → excluded and listed. Never pass raw bytes through.
4. **Valid JSONL.** Records are redacted on the parsed value and re-serialized;
   unchanged lines are kept byte-for-byte.
5. **Final re-scan gates the ZIP.** `rescan_staging` must pass (processing staged
   files again must be a no-op) and returns per-file hashes; after the review
   prompt it is run again and must give identical hashes; `write_zip` only
   archives bytes matching those hashes and then verifies the ZIP.
6. **No original-file hashes/sizes in the manifest** (they would let anyone
   confirm guesses of redacted values).
7. **Export exactly what was attributed.** Discovery records
   `scanned_bytes`/`scanned_sha256`; staging exports that prefix only and drops
   the session if the prefix hash changed (live files keep growing).
8. **Attribution is conservative.** Every recorded `cwd` must be inside the repo;
   Claude dir-name must equal the encoded launch `cwd`; Codex `session_meta.id`
   must match the file-name UUID. Otherwise exclude *and report*.
   Sessions from other projects are only counted (never listed).
9. **Dates from event timestamps only** (top-level `timestamp`), never mtimes.
10. **Credential files never exported** (`discovery.is_credential_file`).

## Verified schema facts (checked against real local data, 2026-10)
- Codex rollouts: every line `{timestamp, type, payload}`; line 1 is
  `session_meta` (payload: `id`, `cwd`, `timestamp`, `creator_user_id`,
  `creator_account_id`, …). `turn_context.payload.cwd` repeats the cwd. Some files
  contain extra `session_meta` lines with *different* ids (parent/fork threads)
  but the same cwd. Resumed sessions append to the same file (multi-day spans).
  Timestamps are `YYYY-MM-DDTHH:MM:SS.mmmZ`. Folder date = local start date.
- Codex `history.jsonl`: `{session_id, ts (int), text}`; `session_index.jsonl`:
  `{id, thread_name, updated_at}`.
- Claude project dir name == `re.sub(r"[^A-Za-z0-9]", "-", first_cwd)` for all
  observed files. Later `cwd` values were always subfolders of the first.
  Records' `sessionId` == file stem.
- Claude `file-history-snapshot.snapshot.trackedFileBackups` maps relative path →
  `{backupFileName, version, backupTime, realParentDir}`; original path =
  `realParentDir/basename(key)`. `file-history-delta` has `trackingPath` + `backup`
  of the same shape. `backupFileName` may be null.
- Claude session folder `<sessionId>/` holds `subagents/agent-<id>.jsonl` (+
  `.meta.json`) and `tool-results/*.txt`.
- Claude `history.jsonl`: `{display, pastedContents, timestamp (int), project, sessionId}`.
- Claude account-ish keys observed: `userEmail`, `organizationUuid`,
  `user_identity`, `hostCredential`.
Do not add support for fields you have not verified; exclude-and-report instead.
When inspecting real data, print only keys/types/counts or masked shapes
(letters→`a`, digits→`9`), never values.

## Working on detectors
- Add a detector with `_d(name, category, pattern, hints=..., ci=..., group=..., validator=...)`.
  `hints` are substrings that must occur for the regex to run (big speed win);
  keep them a superset of what the pattern can match.
- Avoid unbounded prefixes like `[A-Za-z0-9]*` before a keyword (quadratic on
  long base64 blobs). Bound repetitions.
- Placeholders contain `[REDACTED`; validators must reject values containing it
  so redaction is idempotent (the re-scan depends on that).
- `Redactor.redact_text` runs every detector twice: on the text, and (if it
  contains `\` or ESC) on `escape_blanked_view(text)` — a same-length copy with
  escape sequences/ANSI codes blanked — splicing the spans into the real text.
  `Detector.sub(text, view)` relies on view and text having equal length.
- The structural safety scan (`_structural_view`) reads keys + values with JSON
  punctuation; a hit means a match spans several JSON values → record omitted.
- Values under sensitive keys are redacted whatever their type; check real data
  (types only) before widening `_SENSITIVE_KEY_SUFFIXES` — e.g. a bare `tokens`
  suffix would wipe usage counters like `input_tokens`.
- Add positive *and* false-positive tests in `tests/test_privacy.py`
  (`test_no_false_positives_on_common_text`).

## Commands
```bash
python3 -m unittest discover -s tests          # full suite (~1 s)
python3 export_sessions.py --repo "$PWD" --from 2026-10-01 --to 2026-10-17 --dry-run
```
Run the suite on the oldest supported Python too (`/usr/bin/python3` is 3.9 on macOS).
Performance reference: ~0.45 s/MB per processing pass on Apple Silicon.
