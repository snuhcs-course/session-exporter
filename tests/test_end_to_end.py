"""End-to-end tests against synthetic Codex / Claude Code data directories."""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from datetime import date
from pathlib import Path
from unittest import mock

import helpers as h
from helpers import ALL_SECRET_VALUES, PRIVATE_KEY, SECRETS
from session_exporter import cli
from session_exporter.discovery import discover
from session_exporter.paths import RepoMatcher, claude_project_dirname
from session_exporter.privacy import OMITTED_RECORD_TYPE
from session_exporter.timeutil import DateRange

IDS = {k: f"0199{n:04d}-aaaa-7bbb-8ccc-{n:012d}" for n, k in enumerate(
    ["A", "B", "C", "D", "E", "F", "G", "H", "PARENT", "NOCWD"], start=1)}
CIDS = {k: f"c1a0de00-0000-4000-8000-{n:012d}" for n, k in enumerate(
    ["P", "Q", "R", "S", "T", "OLD"], start=1)}


class Fixture:
    """Builds a tmp dir with a repo, look-alike dirs and both tools' data."""

    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="se-test-"))
        self.work = self.tmp / "work"
        self.repo = self.work / "team-repo"
        (self.repo / "src").mkdir(parents=True)
        (self.work / "team-repo-old").mkdir()
        (self.work / "team" / "repo").mkdir(parents=True)  # encodes like team-repo
        self.codex = self.tmp / "codex-home"
        self.claude = self.tmp / "claude-home"
        self.out = self.tmp / "out" / "export.zip"
        self._build_codex()
        self._build_claude()
        self.before = {**h.snapshot_tree(self.codex), **h.snapshot_tree(self.claude)}

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    # ------------------------------------------------------------- Codex --
    def _build_codex(self):
        repo, c = str(self.repo), self.codex
        t = "2026-10-05T10:00:00.000Z"
        h.codex_rollout(c, IDS["A"], t, [
            h.codex_meta(IDS["A"], repo, t), h.codex_turn(repo, t),
            h.codex_message("user", f"my email is {SECRETS['email']}", t),
            *h.codex_tool_call("cat .env", f"OPENAI_API_KEY={SECRETS['openai']}\nDB_PASSWORD={SECRETS['password']}", t),
            h.codex_message("assistant", "Done.", "2026-10-05T10:05:00.000Z"),
        ])
        t = "2026-10-06T09:00:00.000Z"
        sub = str(self.repo / "src")
        h.codex_rollout(c, IDS["B"], t, [h.codex_meta(IDS["B"], sub, t), h.codex_turn(sub, t),
                                         h.codex_message("user", "subdir work", t)])
        old = str(self.work / "team-repo-old")
        h.codex_rollout(c, IDS["C"], t, [h.codex_meta(IDS["C"], old, t), h.codex_turn(old, t),
                                         h.codex_message("user", "UNRELATED-PROJECT-TEXT", t)])
        # Resumed: file lives in the 09/28 folder, continues on 10/02, and also
        # carries a parent thread's session_meta (as forked sessions do).
        t0, t1 = "2026-09-28T23:00:00.000Z", "2026-10-02T01:00:00.000Z"
        h.codex_rollout(c, IDS["D"], t0, [
            h.codex_meta(IDS["D"], repo, t0), h.codex_meta(IDS["PARENT"], repo, t0, parent=None),
            h.codex_turn(repo, t0), h.codex_message("user", "day one", t0),
            h.codex_turn(repo, t1), h.codex_message("user", "resumed later", t1)])
        # Unrecognized format: first record is not session_meta.
        h.codex_rollout(c, IDS["E"], t, [h.codex_turn(repo, t), h.codex_message("user", "x", t)])
        # Ambiguous: working directory leaves the repository.
        h.codex_rollout(c, IDS["F"], t, [h.codex_meta(IDS["F"], repo, t), h.codex_turn(repo, t),
                                         h.codex_turn("/tmp/elsewhere", t)])
        # Malformed middle line (containing a secret) + incomplete trailing line.
        h.codex_rollout(c, IDS["G"], t, [
            h.codex_meta(IDS["G"], repo, t), h.codex_turn(repo, t),
            ('{"timestamp":"' + t + '","type":"response_item","payload":{"text":"'
             + SECRETS["github"]).encode(),
            h.codex_message("user", "after the broken line", t),
        ], raw_suffix=b'{"timestamp":"2026-10-06T09:01:00.000Z","type":"respo')
        # Codex session_meta without any cwd: cannot be tied to any project.
        h.codex_rollout(c, IDS["NOCWD"], t, [{"timestamp": t, "type": "session_meta",
                                              "payload": {"id": IDS["NOCWD"]}}])
        # Out of range.
        t = "2026-08-01T10:00:00.000Z"
        h.codex_rollout(c, IDS["H"], t, [h.codex_meta(IDS["H"], repo, t), h.codex_turn(repo, t)],
                        archived=True)
        h.write_jsonl(c / "history.jsonl", [
            ("[" * 5000 + "]" * 5000).encode(),  # pathological nesting must not crash
            {"session_id": IDS["A"], "ts": 1791000000, "text": f"use key {SECRETS['anthropic']}"},
            {"session_id": IDS["C"], "ts": 1791000001, "text": "UNRELATED-PROJECT-TEXT"},
        ])
        h.write_jsonl(c / "session_index.jsonl", [
            {"id": IDS["A"], "thread_name": "Fix login", "updated_at": "2026-10-05T10:05:00Z"},
            {"id": IDS["C"], "thread_name": "UNRELATED-PROJECT-TEXT", "updated_at": "x"}])
        (c / "auth.json").write_text(json.dumps({"OPENAI_API_KEY": "AUTH-FILE-MARKER"}))
        (c / "config.toml").write_text("CONFIG-FILE-MARKER")
        (c / "shell_snapshots").mkdir()
        (c / "shell_snapshots" / f"{IDS['A']}.sh").write_text("export SHELL_SNAPSHOT_MARKER=1")

    # ------------------------------------------------------------ Claude --
    def _build_claude(self):
        repo, c = str(self.repo), self.claude
        sid, t = CIDS["P"], "2026-10-07T12:00:00.000Z"
        h.claude_session(c, sid, [
            h.claude_snapshot(t, {"src/app.py": ("aaaa1111@v1", repo),
                                  ".env": ("bbbb2222@v1", repo),
                                  "logo.png": ("eeee5555@v1", repo),
                                  "../../etc/hosts": ("cccc3333@v1", "/etc")}),
            h.claude_user(sid, repo, t, f"I am {SECRETS['student_name']}, phone {SECRETS['phone']}"),
            h.claude_tool_use(sid, repo, t, "Bash", {"command": "env", "headers": {"apiKey": "plain-api-key-value"}}),
            h.claude_tool_result(sid, repo, t, [{"type": "text", "text": PRIVATE_KEY}]),
            h.claude_user(sid, str(self.repo / "src"), "2026-10-08T01:00:00.000Z", "cd into src"),
            {"type": "ai-title", "aiTitle": "Debug login", "sessionId": sid},
        ], cwd=repo)
        sdir = c / "projects" / claude_project_dirname(repo) / sid
        (sdir / "tool-results").mkdir(parents=True)
        (sdir / "tool-results" / "out1.txt").write_text(f"GITHUB_TOKEN={SECRETS['github']}\n")
        (sdir / "tool-results" / "a b.txt").write_text("first")
        (sdir / "tool-results" / "a_b.txt").write_text("second")
        (sdir / "subagents").mkdir()
        h.write_jsonl(sdir / "subagents" / "agent-1.jsonl", [
            h.claude_user(sid, repo, t, f"subagent sees {SECRETS['aws_id']}")])
        (sdir / "secret.key").write_text("KEY-FILE-MARKER")
        fh = c / "file-history" / sid
        fh.mkdir(parents=True)
        (fh / "aaaa1111@v1").write_text(f"API_TOKEN = '{SECRETS['openai']}'\nprint('hi')\n")
        (fh / "bbbb2222@v1").write_text("ENV-FILE-MARKER=1")
        (fh / "cccc3333@v1").write_text("OUTSIDE-FILE-MARKER")
        (fh / "dddd4444@v1").write_text("UNMAPPED-FILE-MARKER")
        (fh / "eeee5555@v1").write_bytes(b"\x00\x01binary")
        # Collision: /work/team/repo encodes to the same directory name.
        coll = str(self.work / "team" / "repo")
        h.claude_session(c, CIDS["Q"], [h.claude_user(CIDS["Q"], coll, t, "COLLISION-TEXT")],
                         project_dir=claude_project_dirname(repo))
        # Directory name does not match the recorded cwd.
        h.claude_session(c, CIDS["R"], [h.claude_user(CIDS["R"], repo, t, "MISFILED-TEXT")],
                         project_dir="-somewhere-else")
        # No cwd metadata, in the repository's directory.
        h.claude_session(c, CIDS["S"], [{"type": "summary", "summary": "NO-CWD-TEXT",
                                         "leafUuid": "x"}], project_dir=claude_project_dirname(repo))
        # Unrelated project.
        h.claude_session(c, CIDS["OLD"], [h.claude_user(CIDS["OLD"], str(self.work / "team-repo-old"),
                                                        t, "UNRELATED-PROJECT-TEXT")],
                         cwd=str(self.work / "team-repo-old"))
        h.write_jsonl(c / "history.jsonl", [
            {"display": f"prompt with {SECRETS['email']}", "pastedContents": {}, "timestamp": 1,
             "project": repo, "sessionId": sid},
            {"display": "UNRELATED-PROJECT-TEXT", "pastedContents": {}, "timestamp": 2,
             "project": "/x", "sessionId": CIDS["OLD"]}])
        (c / ".credentials.json").write_text('{"token": "CREDENTIALS-MARKER"}')
        (c / "settings.json").write_text('{"SETTINGS-MARKER": 1}')
        (c / "sessions").mkdir()
        (c / "sessions" / "123.key").write_text("SESSION-KEY-MARKER")
        (c / "session-env" / sid).mkdir(parents=True)
        (c / "session-env" / sid / "env").write_text("SESSION-ENV-MARKER")

    # ------------------------------------------------------------ helpers --
    def args(self, *extra, frm="2026-10-01", to="2026-10-17"):
        return ["--repo", str(self.repo), "--from", frm, "--to", to, "--timezone", "UTC",
                "--codex-home", str(self.codex), "--claude-home", str(self.claude),
                "--redact-term", SECRETS["student_name"], *extra]

    def run(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def originals_unchanged(self):
        return {**h.snapshot_tree(self.codex), **h.snapshot_tree(self.claude)} == self.before


MARKERS = ["UNRELATED-PROJECT-TEXT", "COLLISION-TEXT", "MISFILED-TEXT", "NO-CWD-TEXT",
           "AUTH-FILE-MARKER", "CONFIG-FILE-MARKER", "SHELL_SNAPSHOT_MARKER", "KEY-FILE-MARKER",
           "ENV-FILE-MARKER", "OUTSIDE-FILE-MARKER", "UNMAPPED-FILE-MARKER", "CREDENTIALS-MARKER",
           "SETTINGS-MARKER", "SESSION-KEY-MARKER", "SESSION-ENV-MARKER"]


class DiscoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fx = Fixture()

    @classmethod
    def tearDownClass(cls):
        cls.fx.cleanup()

    def _discover(self, frm=date(2026, 10, 1), to=date(2026, 10, 17), exact=False):
        rng = DateRange(frm, to, "UTC")
        return discover(["codex", "claude"], RepoMatcher(str(self.fx.repo)), rng, exact=exact,
                        codex_dir=str(self.fx.codex), claude_dir=str(self.fx.claude))

    def _status(self, d):
        return {s.session_id: (s.status, s.reason) for s in d.sessions}

    def test_attribution(self):
        st = self._status(self._discover())
        for k in ("A", "B", "D", "G"):
            self.assertEqual(st[IDS[k]][0], "selected", k)
        self.assertEqual(st[CIDS["P"]][0], "selected")
        self.assertNotIn(IDS["C"], st)        # unrelated: not even listed
        self.assertNotIn(CIDS["OLD"], st)
        self.assertEqual(st[IDS["E"]][0], "excluded")  # its turn_context cwd is the repo
        self.assertIn("not session_meta", st[IDS["E"]][1])
        self.assertEqual(st[IDS["F"]][0], "excluded")
        self.assertIn("outside", st[IDS["F"]][1])
        self.assertEqual(st[IDS["H"]][0], "out_of_range")
        self.assertIn("collision", st[CIDS["Q"]][1])
        self.assertIn("does not match", st[CIDS["R"]][1])
        self.assertEqual(st[CIDS["S"]][0], "unattributable")

    def test_exact_mode_excludes_subdirectory_sessions(self):
        st = self._status(self._discover(exact=True))
        self.assertEqual(st[IDS["B"]][0], "excluded")
        self.assertEqual(st[IDS["A"]][0], "selected")

    def test_resumed_session_spanning_days(self):
        # Only the resumed day is inside the range; the file sits in 09/28.
        d = self._discover(frm=date(2026, 10, 2), to=date(2026, 10, 2))
        s = next(x for x in d.sessions if x.session_id == IDS["D"])
        self.assertEqual(s.status, "selected")
        self.assertEqual(s.events_in_range, 2)
        self.assertEqual(s.first_ts.day, 28)
        # The parent thread's session_meta does not change the session id.
        self.assertNotIn(IDS["PARENT"], {x.session_id for x in d.sessions})

    def test_date_boundaries(self):
        st = self._status(self._discover(frm=date(2026, 10, 8), to=date(2026, 10, 8)))
        self.assertEqual(st[CIDS["P"]][0], "selected")  # last event 10-08 01:00
        st = self._status(self._discover(frm=date(2026, 10, 9), to=date(2026, 10, 9)))
        self.assertEqual(st[CIDS["P"]][0], "out_of_range")
        st = self._status(self._discover(frm=date(2026, 9, 1), to=date(2026, 9, 28)))
        self.assertEqual(st[IDS["D"]][0], "selected")   # first event 09-28 23:00 UTC
        self.assertEqual(st[IDS["A"]][0], "out_of_range")


class WindowsPathDiscoveryTest(unittest.TestCase):
    def test_windows_cwd_sessions(self):
        tmp = Path(tempfile.mkdtemp(prefix="se-win-"))
        try:
            claude, codex = tmp / "claude", tmp / "codex"
            win_repo = r"C:\Users\Student\team-repo"
            t = "2026-10-05T10:00:00.000Z"
            h.claude_session(claude, CIDS["T"], [
                h.claude_user(CIDS["T"], win_repo, t, "hi"),
                h.claude_user(CIDS["T"], win_repo + r"\src", t, "sub")], cwd=win_repo)
            h.codex_rollout(codex, IDS["A"], t, [h.codex_meta(IDS["A"], "c:/users/student/TEAM-REPO", t)])
            h.codex_rollout(codex, IDS["B"], t, [h.codex_meta(IDS["B"], r"C:\Users\Student\team-repo-old", t)])
            d = discover(["codex", "claude"], RepoMatcher(win_repo),
                         DateRange(date(2026, 10, 1), date(2026, 10, 31), "UTC"),
                         codex_dir=str(codex), claude_dir=str(claude))
            st = {s.session_id: s.status for s in d.sessions}
            self.assertEqual(st, {IDS["A"]: "selected", CIDS["T"]: "selected"})
            self.assertEqual(claude_project_dirname(win_repo), "C--Users-Student-team-repo")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class ExportTest(unittest.TestCase):
    def setUp(self):
        self.fx = Fixture()

    def tearDown(self):
        self.fx.cleanup()

    def _zip_texts(self):
        with zipfile.ZipFile(self.fx.out) as zf:
            return {n: zf.read(n).decode("utf-8") for n in zf.namelist()}

    def assertNoLeaks(self, *texts):
        blob = "\n".join(texts)
        for v in ALL_SECRET_VALUES + MARKERS:
            self.assertNotIn(v, blob)

    def test_full_export(self):
        code, out, err = self.fx.run(*self.fx.args("--output", str(self.fx.out), "--yes"))
        self.assertEqual(code, 0, out + err)
        files = self._zip_texts()
        self.assertNoLeaks(out, err, *files.values())
        self.assertTrue(self.fx.originals_unchanged())

        manifest = json.loads(files["manifest.json"])
        exported = {s["session_id"]: s for s in manifest["sessions"]}
        self.assertEqual(set(exported), {IDS["A"], IDS["B"], IDS["D"], IDS["G"], CIDS["P"]})
        self.assertEqual(manifest["privacy"]["final_rescan"], "passed")
        self.assertIn("cannot guarantee", manifest["privacy"]["disclaimer"])
        reasons = {e["session_id"]: e["reason"] for e in manifest["excluded_sessions"]}
        self.assertEqual(set(reasons), {IDS["E"], IDS["F"], CIDS["Q"], CIDS["R"], CIDS["S"]})
        self.assertTrue(exported[IDS["D"]]["multi_day"])
        self.assertEqual(exported[IDS["B"]]["repository_match"], "subdirectory")
        self.assertNotIn(str(Path.home()), files["manifest.json"])
        self.assertNotIn("source_sha256", files["manifest.json"])  # would allow guessing
        self.assertNotIn(IDS["C"], files["manifest.json"])           # other project
        self.assertNotIn(IDS["NOCWD"], files["manifest.json"])       # unattributable, not ours
        self.assertEqual(manifest["summary"]["other_or_unattributable_session_files_skipped"],
                         {"claude": 1, "codex": 1, "codex_unattributable": 1})
        # both names that sanitize alike are kept
        p = f"claude/{CIDS['P']}/session-files/tool-results/"
        self.assertIn(p + "a_b.txt", files)
        self.assertIn(p + "a_b~2.txt", files)

        # Every JSONL file is still valid JSONL.
        for name, text in files.items():
            if name.endswith(".jsonl"):
                for line in text.splitlines():
                    json.loads(line)

        # Malformed lines became placeholder records.
        g = next(v for k, v in files.items() if IDS["G"] in k and "rollout-" in k)
        kinds = [json.loads(l) for l in g.splitlines()]
        omitted = [r["reason"] for r in kinds if r.get("type") == OMITTED_RECORD_TYPE]
        self.assertEqual(omitted, ["malformed_json", "incomplete_trailing_line"])

        # Supporting files: included and excluded as expected.
        p = f"claude/{CIDS['P']}/"
        self.assertIn(p + "session-files/tool-results/out1.txt", files)
        self.assertIn(p + "session-files/subagents/agent-1.jsonl", files)
        self.assertIn(p + "file-history/aaaa1111@v1", files)
        self.assertIn(p + "history.jsonl", files)
        self.assertIn(f"codex/{IDS['A']}/history.jsonl", files)
        self.assertIn(f"codex/{IDS['A']}/session_index.jsonl", files)
        self.assertFalse(any(n.endswith((".key", "bbbb2222@v1", "cccc3333@v1", "dddd4444@v1",
                                         "eeee5555@v1")) for n in files))
        skipped = {s["path"]: s["reason"] for s in exported[CIDS["P"]]["skipped_files"]}
        self.assertIn("credential", skipped["session-files/secret.key"])
        self.assertIn("credential or environment", skipped["file-history/bbbb2222@v1"])
        self.assertIn("outside", skipped["file-history/cccc3333@v1"])
        self.assertIn("no recorded original", skipped["file-history/dddd4444@v1"])
        self.assertIn("binary", skipped["file-history/eeee5555@v1"])

    def test_dry_run_writes_nothing(self):
        code, out, err = self.fx.run(*self.fx.args("--dry-run"))
        self.assertEqual(code, 0, out + err)
        self.assertIn("Dry run complete", out)
        self.assertIn("openai_api_key", out)
        self.assertIn("cannot guarantee", out)
        self.assertFalse(self.fx.out.parent.exists())
        self.assertNoLeaks(out, err)
        self.assertTrue(self.fx.originals_unchanged())

    def test_review_step_required(self):
        # Non-interactive without --yes: fail closed, nothing written.
        with mock.patch("sys.stdin", io.StringIO("y\n")):
            code, out, _ = self.fx.run(*self.fx.args("--output", str(self.fx.out)))
        self.assertEqual(code, cli.EXIT_CANCELLED)
        self.assertFalse(self.fx.out.exists())
        # Interactive "no".
        with mock.patch.object(cli, "_confirm", return_value=False):
            code, _, _ = self.fx.run(*self.fx.args("--output", str(self.fx.out)))
        self.assertEqual(code, cli.EXIT_CANCELLED)
        self.assertFalse(self.fx.out.exists())
        # Interactive "yes".
        with mock.patch.object(cli, "_confirm", return_value=True):
            code, _, _ = self.fx.run(*self.fx.args("--output", str(self.fx.out)))
        self.assertEqual(code, 0)
        self.assertTrue(self.fx.out.exists())

    def test_existing_output_requires_force(self):
        self.fx.out.parent.mkdir(parents=True)
        self.fx.out.write_bytes(b"old")
        code, _, err = self.fx.run(*self.fx.args("--output", str(self.fx.out), "--yes"))
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertEqual(self.fx.out.read_bytes(), b"old")
        code, _, _ = self.fx.run(*self.fx.args("--output", str(self.fx.out), "--yes", "--force"))
        self.assertEqual(code, 0)
        self.assertTrue(zipfile.is_zipfile(self.fx.out))

    def test_output_inside_data_dir_rejected(self):
        bad = self.fx.claude / "export.zip"
        code, _, _ = self.fx.run(*self.fx.args("--output", str(bad), "--yes"))
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertFalse(bad.exists())

    def test_staged_files_edited_during_review_abort(self):
        from session_exporter import exporter
        staged = {}
        real_stage = exporter.stage

        def capture(*a, **kw):
            res = real_stage(*a, **kw)
            staged["dir"] = res.staging_dir
            return res

        def tamper(prompt):
            victim = next(p for p in staged["dir"].rglob("*.jsonl"))
            with open(victim, "ab") as fh:
                fh.write(('{"t":"' + SECRETS["github"] + '"}\n').encode())
            return True

        with mock.patch("session_exporter.cli.stage", side_effect=capture), \
                mock.patch.object(cli, "_confirm", side_effect=tamper):
            code, out, err = self.fx.run(*self.fx.args("--output", str(self.fx.out)))
        self.assertEqual(code, cli.EXIT_UNSAFE)
        self.assertIn("changed during the review", err)
        self.assertFalse(self.fx.out.exists())
        self.assertNoLeaks(out, err)

    def test_write_zip_refuses_bytes_that_were_not_rescanned(self):
        from session_exporter import exporter
        from session_exporter.privacy import Redactor
        d = discover(["codex"], RepoMatcher(str(self.fx.repo)),
                     DateRange(date(2026, 10, 5), date(2026, 10, 5), "UTC"),
                     codex_dir=str(self.fx.codex))
        staging = exporter.make_staging_dir()
        try:
            res = exporter.stage(d, Redactor(), staging)
            exporter.write_manifest(res, {"x": 1})
            problems, hashes = exporter.rescan_staging(res, Redactor(), extra=["manifest.json"])
            self.assertEqual(problems, [])
            arc = res.sessions[0].files[0].arc
            with open(staging.joinpath(*arc.split("/")), "ab") as fh:
                fh.write(b'{"late":"edit"}\n')
            with self.assertRaises(exporter.ExportAborted):
                exporter.write_zip(res, self.fx.out, False, hashes)
            self.assertFalse(self.fx.out.exists())
        finally:
            exporter.remove_staging(staging)

    def test_growing_or_rewritten_session_file(self):
        from session_exporter import exporter
        from session_exporter.privacy import Redactor
        rng = DateRange(date(2026, 10, 5), date(2026, 10, 5), "UTC")
        d = discover(["codex"], RepoMatcher(str(self.fx.repo)), rng, codex_dir=str(self.fx.codex))
        sess = next(s for s in d.sessions if s.session_id == IDS["A"])
        # Appended after attribution (e.g. a record from another project).
        with open(sess.source, "ab") as fh:
            fh.write((json.dumps(h.codex_turn("/other/project", "2026-10-05T11:00:00Z")) + "\n").encode())
        staging = exporter.make_staging_dir()
        try:
            res = exporter.stage(d, Redactor(), staging)
            text = staging.joinpath(*res.sessions[0].files[0].arc.split("/")).read_text()
            self.assertNotIn("/other/project", text)
        finally:
            exporter.remove_staging(staging)
        # Rewritten in place: dropped, not exported.
        sess.source.write_bytes(b"{}\n" * 10000)
        staging = exporter.make_staging_dir()
        try:
            res = exporter.stage(d, Redactor(), staging)
            self.assertIn(IDS["A"], [s.session_id for s, _ in res.dropped])
        finally:
            exporter.remove_staging(staging)

    def test_final_rescan_failure_aborts(self):
        # Simulate a redaction bug: staging writes raw content. The re-scan
        # must catch it, refuse to build the ZIP, and not echo the secret.
        from session_exporter import exporter, privacy

        def no_redaction(raw, arc, redactor):
            return privacy.FileResult(data=raw)

        with mock.patch.object(exporter, "process_file", side_effect=no_redaction):
            code, out, err = self.fx.run(*self.fx.args("--output", str(self.fx.out), "--yes"))
        self.assertEqual(code, cli.EXIT_UNSAFE)
        self.assertIn("FAILED", out)
        self.assertFalse(self.fx.out.exists())
        self.assertNoLeaks(out, err)

    def test_tool_filter_and_nothing_selected(self):
        code, out, _ = self.fx.run(*self.fx.args("--tool", "claude", "--dry-run"))
        self.assertEqual(code, 0)
        self.assertNotIn(IDS["A"], out)
        code, out, _ = self.fx.run(*self.fx.args("--dry-run", frm="2025-01-01", to="2025-01-02"))
        self.assertEqual(code, cli.EXIT_NOTHING)

    def test_usage_errors(self):
        code, _, _ = self.fx.run("--repo", "relative/path", "--from", "2026-10-01",
                                 "--to", "2026-10-02", "--dry-run")
        self.assertEqual(code, cli.EXIT_USAGE)
        code, _, _ = self.fx.run(*self.fx.args("--dry-run", frm="2026-10-05", to="2026-10-01"))
        self.assertEqual(code, cli.EXIT_USAGE)
        code, _, _ = self.fx.run(*self.fx.args())  # no --output, no --dry-run
        self.assertEqual(code, cli.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
