# Session Exporter

Export the **Codex CLI** and **Claude Code** session histories that belong to one
project repository and date range into a **redacted ZIP archive** — for example to
submit your AI-agent usage logs for a course project.

- Runs entirely on your computer. Nothing is uploaded or sent anywhere.
- Never modifies the original session files (they are only opened for reading).
- Redacts API keys, tokens, passwords, private keys and personal information
  in the exported copies, re-scans everything, and asks you to review before the
  ZIP is created.

> **Important — automated redaction cannot guarantee that all sensitive
> information is removed.** Detection is pattern-based. Names, free-form personal
> details, encoded data or unusual secret formats can slip through. Always review
> the export before sharing it, and if a real secret was ever exposed in a
> session, **revoke and rotate it** — redacting the copy is not enough.

---

## Supported features

| Area | What is supported |
| --- | --- |
| Tools | Codex CLI (`--tool codex`), Claude Code (`--tool claude`), or both (`--tool both`, default) |
| Platforms | macOS, Linux, Windows (and WSL, run inside WSL); Python 3.9+; no third-party packages |
| Session selection | By recorded working directory (`cwd`) inside the repository, compared by normalized path components; sessions that overlap an inclusive date range based on event timestamps |
| Path handling | Windows drive/UNC/`\\?\` paths, `/` vs `\`, case-insensitive file systems (auto-detected), symbolic links, Unicode (NFC/NFD) names, look-alike directories (`repo` vs `repo-old`) |
| Resumed sessions | Sessions that continue over several days (same file) are selected if any part of their span overlaps the range |
| Ambiguity handling | Sessions that cannot be confidently attributed are excluded and the reason is reported (console + manifest) |
| Supporting files | Codex: matching lines of `history.jsonl` and `session_index.jsonl`. Claude Code: the session folder (subagent transcripts, large tool results), matching `history.jsonl` lines, and `file-history` backups of files inside the repository |
| Privacy | Secret/PII detectors, key-based redaction in nested JSON, home-path anonymization, custom terms (`--redact-term`), fail-closed processing, final re-scan, archive verification |
| Review | `--dry-run` preview; interactive confirmation with a private staging folder you can inspect before the ZIP is written |
| Output | ZIP with `manifest.json` (metadata, hashes, redaction counts, exclusions — never the sensitive values) |
| Tests | 59 automated tests using synthetic Codex / Claude Code fixtures |

---

## Installation

You need **Python 3.9 or newer**. Nothing else is required.

```bash
git clone <this repository URL> session-exporter
cd session-exporter
python3 --version          # Windows: python --version  or  py --version
```

Run it directly from the folder (no installation):

```bash
python3 export_sessions.py --help
```

Optional: install the `session-exporter` command:

```bash
python3 -m pip install .
session-exporter --help
```

On Windows, if you want to use an IANA time-zone name such as `--timezone Asia/Seoul`,
also run `python -m pip install tzdata`. (The default, your computer's local time
zone, works without it.)

---

## Usage

### 1. Find your repository's absolute path

```bash
cd /path/to/your/team-repo && pwd                 # macOS / Linux / WSL
```
```powershell
cd "C:\Users\student\projects\team-repo"; (Get-Location).Path   # Windows PowerShell
```

### 2. Preview with `--dry-run` (writes nothing)

```bash
python3 export_sessions.py --tool both \
  --repo "/absolute/path/to/team-repo" \
  --from 2026-10-01 --to 2026-10-17 --dry-run
```

```powershell
python .\export_sessions.py --tool both `
  --repo "C:\Users\student\projects\team-repo" `
  --from 2026-10-01 --to 2026-10-17 --dry-run
```

The preview lists:

- **Selected sessions** — tool, session ID, first/last event time, whether the
  session ran in the repository itself (`exact`) or a subfolder (`subdirectory`).
- **Excluded sessions** — sessions that touch the repository but could not be
  confidently attributed, each with a reason.
- **Privacy findings** — counts per detector and the locations
  (`file:line  JSON path  detector`). The sensitive values themselves are never shown.
- The result of the **final re-scan**.

### 3. Export and review

```bash
python3 export_sessions.py --tool both \
  --repo "/absolute/path/to/team-repo" \
  --from 2026-10-01 --to 2026-10-17 \
  --output team-sessions.zip
```

Before writing the ZIP, the tool prints the path of a private staging folder
containing the exact redacted files that will be archived and asks:

```
Redacted copies are staged for inspection at: /tmp/session-export-xxxx
Create ~/.../team-sessions.zip? [y/N]
```

Open the staging folder, check the files, then answer `y`. Any other answer
cancels and nothing is written. The staging folder is deleted afterwards.
The folder is for *reading* only: if any staged file changes before you answer,
the export is aborted, because the archive must contain exactly the bytes that
passed the final re-scan. To hide additional text, run again with
`--redact-term "text"` (repeatable) or exclude the session by narrowing the dates.
In scripts or other non-interactive shells you must pass `--yes`; without it the
export is cancelled (fail closed).

### 4. Check the archive

```bash
unzip -l team-sessions.zip        # macOS / Linux
tar -tf .\team-sessions.zip       # Windows PowerShell (also works on macOS)
```

### Options

| Option | Meaning |
| --- | --- |
| `--tool codex\|claude\|both` | Which agent's sessions to export (default `both`) |
| `--repo PATH` | **Absolute** path of the project repository (required) |
| `--from YYYY-MM-DD`, `--to YYYY-MM-DD` | Inclusive date range (required) |
| `--output FILE.zip` | ZIP to create (required unless `--dry-run`; must end in `.zip`) |
| `--dry-run` | Preview only; no archive is written (redacted copies are staged in a private temp folder and deleted) |
| `--yes` | Skip the interactive confirmation (needed in non-interactive shells) |
| `--force` | Overwrite an existing output file |
| `--timezone local\|UTC\|Area/City` | Time zone used to interpret the dates (default: your local time zone) |
| `--exact` | Only sessions started exactly in `--repo`, not in its subfolders |
| `--path-case auto\|sensitive\|insensitive` | Case sensitivity for macOS/Linux paths (default: detected from the file system; Windows paths are always case-insensitive) |
| `--redact-term TEXT` | Extra text to redact, e.g. your name or student ID (repeatable, case-insensitive) |
| `--keep-paths` | Do not anonymize home-directory paths and user names |
| `--no-file-history` | Do not include Claude Code file-history backups |
| `--show-all-findings` | List every finding location instead of the first 50 |
| `--codex-home DIR`, `--claude-home DIR` | Use a different data directory (defaults: `$CODEX_HOME` or `~/.codex`; `$CLAUDE_CONFIG_DIR` or `~/.claude`) |

Exit codes: `0` success, `1` nothing to export, `2` usage error, `3` safety check
failed (no archive written), `4` cancelled at the review step.

---

## How sessions are found

The two tools store sessions differently. Only fields verified in real session
files are used.

| | Codex CLI | Claude Code |
| --- | --- | --- |
| Location | `~/.codex/sessions/YYYY/MM/DD/rollout-<time>-<uuid>.jsonl` and `~/.codex/archived_sessions/` | `~/.claude/projects/<encoded cwd>/<sessionId>.jsonl` |
| Folder meaning | Date the session **started** (local time) | Launch directory with every non-alphanumeric character replaced by `-` (lossy: `team-repo` and `team/repo` collide) |
| Record shape | `{timestamp, type, payload}` | Flat records with `type`, `cwd`, `sessionId`, `timestamp`, `message`, … |
| Working directory | `payload.cwd` of the first `session_meta` record and of every `turn_context` record | `cwd` field on each conversation record (may move into subfolders during a session) |
| Session ID | `session_meta.payload.id` (must equal the UUID in the file name) | File name (`<sessionId>.jsonl`) |
| Resumes / forks | Appended to the same file (spans days); extra `session_meta` records describe parent threads | Same file; spans days |
| Supporting data | `history.jsonl` (`session_id`), `session_index.jsonl` (`id`) | `<sessionId>/subagents/`, `<sessionId>/tool-results/`, `file-history/<sessionId>/`, `history.jsonl` (`sessionId`) |
| Never exported | `auth.json`, `config.toml`, `shell_snapshots/`, `*.sqlite` | `.credentials.json`, `settings*.json`, `sessions/*.key`, `session-env/` |

### Attribution rules

A session is exported only if **all** of these hold:

1. It has working-directory metadata, and **every** recorded `cwd` is the
   repository or a subfolder of it. Comparison uses normalized path components
   (never substrings) and honours case rules. If a recorded path exists on this
   machine its real location (symbolic links resolved) decides — so a folder
   inside the repository that is a symlink to another project does not count;
   paths that no longer exist are compared as written.
2. Codex: the first record is `session_meta` and its `id` matches the file name.
   Claude Code: the project folder name equals the encoded form of the recorded
   launch `cwd` — the folder name alone is never trusted.
3. Its event timestamps overlap the date range: first event ≤ end of `--to` day
   and last event ≥ start of `--from` day (both inclusive, in `--timezone`).
   File modification times are never used.

Sessions that touch the repository but fail a rule are **excluded and reported**
with a reason, for example:

- `working directory moves between the repository and paths outside it`
- `project directory name matches the repository but the recorded cwd does not (path-encoding collision)`
- `project directory name does not match the recorded cwd`
- `no cwd metadata; the project directory name alone is not sufficient evidence`
- `unrecognized Codex format: first record is not session_meta`
- `no parseable event timestamps`

Sessions of other projects — and session files with no usable metadata that
nothing links to the repository — are only counted, never listed, so other
projects' names, IDs and activity times do not appear in the output.

Sessions that are still being written (e.g. the one you are currently using)
are exported exactly as far as they were read during selection; anything
appended afterwards is left out, and a file that was rewritten in the meantime
is dropped with a reason.

---

## Privacy protection

**Detectors** (each match becomes `[REDACTED:<detector>]`):

- Secrets: private key blocks, OpenAI / Anthropic / GitHub / GitLab / Slack /
  Google / Stripe / Hugging Face / npm tokens, AWS keys, JWTs, `Bearer`/`token`
  headers, basic-auth headers, credentials in URLs (`scheme://user:pass@`),
  `password=…` / `PGPASSWORD=…` / `DB_PASS=…` / `비밀번호: …` assignments,
  `mysql -p…` / `sshpass -p …` flags, `*_API_KEY=` / `*_SECRET=` / `*_TOKEN=`
  assignments. Matching also works when a secret is glued to an escape sequence
  (`\n`, `\"`) or a terminal colour code, as happens in tool output and in
  JSON stored inside strings.
- JSON keys: any value (text, number, list or object) under keys such as
  `password`, `api_key`, `apiKey`, `*_token`, `client_secret`, `secrets`,
  `credentials`, `DB_PASS` (`sensitive_field`), the `value` of
  `{"name": "API_KEY", "value": …}` pairs, and known account identifiers
  (`creator_user_id`, `creator_account_id`, `userEmail`, `organizationUuid`,
  `user_identity`, `email`).
- Personal information: e-mail addresses, Korean resident registration numbers,
  phone numbers (Korean and North-American formats), payment card numbers
  (format + Luhn check), long numbers stored as JSON numbers.
- Paths: your home directory becomes `~` (also in Claude's encoded folder names);
  other user names in `/Users/<name>`, `/home/<name>`, `C:\Users\<name>` become
  `[REDACTED:username]`. Disable with `--keep-paths`.
- Anything you add with `--redact-term` (e.g. your name, student ID).

**How redaction is applied**

- JSONL is processed record by record: each line is parsed, every string *and
  key* (at any nesting depth — tool inputs, tool outputs, JSON inside strings)
  is redacted, and the record is re-serialized, so the export is always valid
  JSONL. Lines without findings are kept byte-for-byte (records with duplicate
  keys are always re-serialized so a shadowed value cannot slip through).
- A structural check also reads each record's keys and values together; a
  match that spans several JSON values cannot be redacted in place, so that
  record is dropped (fail closed).
- **Fail closed:** a line that cannot be parsed (malformed or partially written)
  or safely redacted is replaced by
  `{"type":"session_exporter.omitted_line","original_line":N,"reason":"…"}`.
  Other files that cannot be scanned (binary, non-UTF-8, invalid JSON) are left
  out and listed in the manifest. Raw unprocessed content is never copied.
- Credential and authentication files are never exported, even if found inside
  a session folder (`auth.json`, `.credentials.json`, `credentials`, `.env*`,
  `*.env`, `.envrc`, `.pgpass`, `.netrc`, `*.key`, `*.pem`, `id_*`,
  `service-account*`, `client_secret*`, `secrets.*`, `kubeconfig`, SQLite
  databases, …). Claude file-history backups are only exported if they are
  backups of files inside the repository and not one of these.
- **Final re-scan:** after staging, every file is scanned again (all detectors,
  JSONL validity, file names). If anything remains, the export stops and no ZIP is
  written. After your confirmation the staged files are checked again, the ZIP
  is built only from bytes whose hashes match the re-scan, and the finished ZIP
  is verified against those hashes.
- Nothing sensitive is printed: console output, error messages and the manifest
  contain detector names and locations only, never the matched values.

---

## Archive layout

```
manifest.json
codex/<session-id>/rollout-<time>-<session-id>.jsonl
codex/<session-id>/history.jsonl            # your prompts for this session
codex/<session-id>/session_index.jsonl      # thread title
claude/<session-id>/<session-id>.jsonl
claude/<session-id>/history.jsonl
claude/<session-id>/session-files/subagents/agent-*.jsonl
claude/<session-id>/session-files/tool-results/*
claude/<session-id>/file-history/<backup name>
```

`manifest.json` contains: generator version, creation time, platform, the query
(tools, repository, date range with UTC bounds, options), a summary, privacy
information (`final_rescan`, redaction counts per detector, detector list,
disclaimer), and for each session its working directories, first/last event,
event counts, warnings, and per-file source path, SHA-256 of the exported bytes,
redaction counts and omitted lines. Excluded sessions are listed with their
reasons. The manifest deliberately contains **no hash or size of the original
files**: with a known hash, anyone could confirm guesses of a redacted value
(such as a phone number) by trial.

---

## Assumptions and limitations

- Session formats are not formally documented by OpenAI or Anthropic. The
  exporter relies only on fields verified against real files (Codex CLI 0.14x,
  Claude Code 2.1.x). Older or future formats that differ are excluded and
  reported rather than guessed (e.g. legacy Codex files without `session_meta`).
- Real-data verification was done on macOS. Windows support (drive/UNC paths,
  case-insensitive matching, `C--Users-…` project folder names, `%USERPROFILE%`
  data directories) follows the same formats and is covered by synthetic tests,
  but has not been run against real Windows session files yet.
- Only local CLI/IDE sessions are covered. Codex Cloud, Claude remote/web
  sessions, and other app-only histories are not on disk and need their own export.
- Sessions recorded in WSL live in the WSL file system: run the exporter inside
  WSL with the Linux path of the repository.
- Claude Code project folders for very long paths may be truncated by Claude
  Code; such sessions fail the folder-name cross-check and are reported as excluded.
- A session started in a parent folder that later moves into the repository
  (or one that leaves it) is excluded as ambiguous.
- Sessions are selected by overlap of their whole span; a session that started
  before and continued after the range is exported in full (the manifest's
  `events_in_range` shows how many events fall in the range).
- Redaction is pattern-based (see the warning at the top). It does not detect
  names, addresses, or secrets in unknown formats unless you pass
  `--redact-term`. IP addresses are not redacted; neither are passwords in
  positional formats such as `.pgpass` lines (`host:port:db:user:password`)
  printed in tool output, or lowercase `pass: …` in prose (too common in normal
  text, e.g. test results). Uppercase `PASS=`/`DB_PASS=` and all `password`
  spellings are detected.
- Speed is roughly 1 s per MB of session data (both passes); typical course
  repositories export in seconds.

---

## Running the tests

```bash
python3 -m unittest discover -s tests      # or: python3 -m pytest tests
```

All tests use synthetic fixtures built in temporary folders (`tests/helpers.py`);
they never read your real session data. They cover path collisions and look-alike
directories, Windows paths, symbolic links, case sensitivity, date and time-zone
boundaries, resumed multi-day sessions, malformed and partially written JSONL,
secrets in tool outputs, nested JSON fields and keys, credential-file exclusion,
the review step, the final re-scan abort, and immutability of the original files.
