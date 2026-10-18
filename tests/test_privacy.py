import json
import unittest
from pathlib import Path

from helpers import ALL_SECRET_VALUES, PRIVATE_KEY, SECRETS
from session_exporter.privacy import (OMITTED_RECORD_TYPE, Redactor, process_file,
                                      process_jsonl, process_text, rescan_file)

HOME = Path("/Users/student")


def redactor(**kw):
    kw.setdefault("home", HOME)
    return Redactor(**kw)


class DetectorTest(unittest.TestCase):
    def setUp(self):
        self.r = redactor()

    def assertRedacted(self, text, detector):
        out, hits = self.r.redact_text(text)
        self.assertIn(detector, hits, (detector, hits))
        self.assertIn(f"[REDACTED:{detector}]", out)
        return out

    def test_secrets(self):
        cases = {
            f"export OPENAI_API_KEY={SECRETS['openai']}": "openai_api_key",
            f"key is {SECRETS['anthropic']}": "anthropic_api_key",
            f"token {SECRETS['github']}": "github_token",
            f"aws id {SECRETS['aws_id']}": "aws_access_key_id",
            f"jwt {SECRETS['jwt']}": "jwt",
            f"password = {SECRETS['password']}": "password_assignment",
            f"DB_PASSWORD: '{SECRETS['password']}'": "password_assignment",
            f"비밀번호: {SECRETS['password']}": "password_assignment",
            "MY_SERVICE_SECRET=abc123def456ghi789": "secret_assignment",
            "Authorization: Bearer abcdefghijklmnop1234567890": "bearer_token",
            f"postgres://admin:{SECRETS['password']}@db.internal:5432/app": "url_credentials",
            PRIVATE_KEY: "private_key",
        }
        for text, det in cases.items():
            with self.subTest(det=det):
                out = self.assertRedacted(text, det)
                for v in ALL_SECRET_VALUES:
                    self.assertNotIn(v, out)

    def test_unterminated_private_key(self):
        out = self.assertRedacted("-----BEGIN PRIVATE KEY-----\nMIIabc", "private_key")
        self.assertNotIn("MIIabc", out)

    def test_personal_information(self):
        self.assertRedacted(f"mail me at {SECRETS['email']}", "email")
        self.assertRedacted(f"call {SECRETS['phone']}", "phone_number")
        self.assertRedacted(f"rrn {SECRETS['rrn']}", "kr_resident_number")
        self.assertRedacted(f"card {SECRETS['card']}", "credit_card")

    def test_home_paths(self):
        out, _ = self.r.redact_text("/Users/student/team-repo/app.py")
        self.assertEqual(out, "~/team-repo/app.py")
        out, _ = self.r.redact_text("/Users/studentx/repo")  # different user
        self.assertEqual(out, "/Users/[REDACTED:username]/repo")
        out, _ = self.r.redact_text("projects/-Users-student-team-repo/x")
        self.assertEqual(out, "projects/~-team-repo/x")
        out, _ = self.r.redact_text(r"C:\Users\Kim\repo")
        self.assertEqual(out, r"C:\Users\[REDACTED:username]\repo")
        out, _ = redactor(redact_paths=False).redact_text("/Users/student/x")
        self.assertEqual(out, "/Users/student/x")

    def test_windows_home(self):
        r = Redactor(home=Path(r"C:\Users\Student"))
        out, _ = r.redact_text(r"c:\users\student\repo and C:/Users/Student/x")
        self.assertEqual(out, r"~\repo and ~/x")

    def test_custom_terms(self):
        r = redactor(extra_terms=[SECRETS["student_name"], "2026-12345"])
        out, hits = r.redact_text(f"Author: {SECRETS['student_name'].upper()} (2026-12345)")
        self.assertNotIn("GILDONG", out)
        self.assertNotIn("2026-12345", out)
        self.assertEqual(hits.count("custom_term"), 2)

    def test_no_false_positives_on_common_text(self):
        benign = [
            '"max_tokens": 128000', "git@github.com:org/repo.git", "noreply@anthropic.com",
            "1792242920534", "password: str", "self.password = password",
            "password = os.environ.get('PW')", "user@example.com",
            "019bb7a4-cc80-7562-a8c6-9af142de57f4", "csrf_token = generate_csrf_token()",
            "pip install react@18.3.1", "10-17 12:34:56.789 123 45678 90123",
            "input_tokens=1234567890123",
        ]
        for text in benign:
            with self.subTest(text=text):
                out, hits = self.r.redact_text(text)
                self.assertEqual(hits, [])
                self.assertEqual(out, text)

    def test_idempotent(self):
        text = f"OPENAI_API_KEY={SECRETS['openai']} password={SECRETS['password']} /Users/student/x"
        once, _ = self.r.redact_text(text)
        self.assertEqual(self.r.scan_text(once), [])


class JsonTest(unittest.TestCase):
    def setUp(self):
        self.r = redactor()

    def test_nested_sensitive_fields_and_keys(self):
        obj = {"a": {"b": [{"api_key": "plainvalue"}, {"githubToken": "tok"}]},
               "creator_account_id": "acct-1", SECRETS["email"]: 1,
               "deep": [[{"note": f"pw is password={SECRETS['password']}"}]]}
        out, hits = self.r.redact_obj(obj)
        dumped = json.dumps(out)
        self.assertNotIn("plainvalue", dumped)
        self.assertNotIn(SECRETS["email"], dumped)
        self.assertNotIn(SECRETS["password"], dumped)
        self.assertNotIn("acct-1", dumped)
        paths = {p for p, _ in hits}
        self.assertIn("$.a.b[0].api_key", paths)
        self.assertIn("$.a.b[1].githubToken", paths)
        self.assertIn("$.deep[0][0].note", paths)
        self.assertIn("$.<key>", paths)  # redacted key is not echoed in the path

    def test_numbers_and_schema_fields_untouched(self):
        obj = {"input_tokens": 1234, "token_count": {"total": 5}, "signature": "abc"}
        out, hits = self.r.redact_obj(obj)
        self.assertEqual(out, obj)
        self.assertEqual(hits, [])


class JsonlTest(unittest.TestCase):
    def setUp(self):
        self.r = redactor()

    def _lines(self, data):
        return [json.loads(l) for l in data.decode("utf-8").splitlines()]

    def test_tool_outputs_and_json_in_strings(self):
        records = [
            {"type": "response_item", "payload": {
                "type": "function_call_output", "output": f"OPENAI_API_KEY={SECRETS['openai']}\n"}},
            {"type": "response_item", "payload": {
                "type": "function_call",
                "arguments": json.dumps({"command": f"curl -H 'Authorization: Bearer {SECRETS['github']}'"})}},
            {"type": "user", "message": {"content": [
                {"type": "tool_result", "content": [{"type": "text", "text": PRIVATE_KEY}]}]}},
            {"type": "assistant", "message": {"content": [
                {"type": "tool_use", "input": {"env": {"DB_PASSWORD": SECRETS["password"]}}}]}},
        ]
        raw = "".join(json.dumps(r) + "\n" for r in records).encode()
        res = process_jsonl(raw, "s.jsonl", self.r)
        text = res.data.decode()
        for v in ALL_SECRET_VALUES:
            self.assertNotIn(v, text)
        self.assertEqual(len(self._lines(res.data)), 4)  # still valid JSONL, same count
        self.assertEqual(rescan_file(res.data, "s.jsonl", self.r), [])

    def test_unchanged_lines_are_byte_identical(self):
        line = b'{"type": "user",   "message": "hello"}'
        res = process_jsonl(line + b"\n", "s.jsonl", self.r)
        self.assertEqual(res.data, line + b"\n")

    def test_malformed_lines_fail_closed(self):
        good = json.dumps({"type": "user", "text": "ok"}).encode()
        secret_bad = ('{"type": "user", "text": "' + SECRETS["openai"]).encode()  # broken JSON
        raw = b"\n".join([good, secret_bad, b"", b"\xff\xfe not utf8", b"NaN",
                          good + b"\r", b'{"partial": "' + SECRETS["password"].encode()])
        res = process_jsonl(raw, "s.jsonl", self.r)
        out = res.data.decode()
        self.assertNotIn(SECRETS["openai"], out)
        self.assertNotIn(SECRETS["password"], out)
        recs = self._lines(res.data)
        reasons = {r.get("reason") for r in recs if r.get("type") == OMITTED_RECORD_TYPE}
        self.assertEqual(reasons, {"malformed_json", "invalid_utf8", "incomplete_trailing_line"})
        self.assertEqual(res.blank_lines, 1)
        self.assertEqual([n for n, _ in res.omitted_lines], [2, 4, 5, 7])
        self.assertEqual(rescan_file(res.data, "s.jsonl", self.r), [])

    def test_json_escapes_do_not_create_false_matches(self):
        # Source code inside a tool call: escaped quotes/newlines must not be
        # misread (e.g. "\nnoreply@..." or 'password: str\").
        code = 'x = "password: str"\nmail = "noreply@anthropic.com"\n'
        raw = (json.dumps({"input": {"content": code}}) + "\n").encode()
        res = process_jsonl(raw, "s.jsonl", self.r)
        self.assertEqual(res.omitted_lines, [])
        self.assertEqual(res.data, raw)

    def test_numbers_holding_personal_data(self):
        card = int(SECRETS["card"].replace(" ", ""))
        raw = (json.dumps({"card": card, "count": 42, "ts": 1792242920534}) + "\n").encode()
        res = process_jsonl(raw, "s.jsonl", self.r)
        out = json.loads(res.data)
        self.assertEqual(out["card"], "[REDACTED:credit_card]")
        self.assertEqual((out["count"], out["ts"]), (42, 1792242920534))

    def test_any_value_type_under_sensitive_keys(self):
        obj = {"password": 98765, "secrets": ["Hunter2!secret"], "credentials": {"u": "x"},
               "passwords": ["pw-list-1"], "tokens": "abc123def456ghi789",
               "headers": {"Authorization": "Basic dXNlcjpwYXNz"}, "input_tokens": 1234,
               "env": [{"name": "DB_PASS", "value": "pa55word"}, {"name": "HOME", "value": "/h"}],
               "max_tokens": 4096, "flag": True, "api_key": None}
        res = process_jsonl((json.dumps(obj) + "\n").encode(), "s.jsonl", self.r)
        out = json.loads(res.data)
        for k in ("password", "secrets", "credentials", "passwords", "tokens"):
            self.assertEqual(out[k], "[REDACTED:sensitive_field]")
        self.assertEqual(out["headers"]["Authorization"], "[REDACTED:sensitive_field]")
        self.assertEqual(out["input_tokens"], 1234)
        self.assertEqual(res.omitted_lines, [])
        self.assertEqual(out["env"][0]["value"], "[REDACTED:sensitive_field]")
        self.assertEqual(out["env"][1]["value"], "/h")
        self.assertEqual((out["max_tokens"], out["flag"], out["api_key"]), (4096, True, None))

    def test_match_spanning_json_structure_fails_closed(self):
        # Backstop: with the key rule disabled, the pair is only visible when
        # key and value are read together -> the record is dropped, not leaked.
        from unittest import mock
        from session_exporter import privacy
        raw = (json.dumps({"db_password": "abcd1234efgh5678"}) + "\n").encode()
        with mock.patch.object(privacy, "is_sensitive_key", return_value=False):
            res = process_jsonl(raw, "s.jsonl", self.r)
        self.assertEqual(res.omitted_lines, [(1, "redaction_error")])
        self.assertNotIn(b"abcd1234efgh5678", res.data)
        res = process_jsonl((json.dumps({"비밀번호": "abcd1234"}) + "\n").encode(), "s.jsonl", self.r)
        self.assertEqual(json.loads(res.data)["비밀번호"], "[REDACTED:sensitive_field]")

    def test_secrets_glued_to_escape_sequences(self):
        inner = json.dumps({"output": "x\n" + SECRETS["github"] + "\n" + SECRETS["aws_id"]})
        ansi = "\x1b[1m" + SECRETS["openai"] + "\x1b[0m and \\u001b[31m" + SECRETS["anthropic"]
        quoted = 'export PASSWORD=\\"' + SECRETS["password"] + '\\"'
        # JSON printed by a command, wrapped in JSON, stored in a JSON string
        nested = json.dumps({"output": json.dumps({"body": "x\n" + SECRETS["jwt"]
                                                    + "\x1b[1m" + SECRETS["email"]})})
        obj = {"arguments": inner, "output": ansi, "cmd": quoted, "nested": nested}
        res = process_jsonl((json.dumps(obj) + "\n").encode(), "s.jsonl", self.r)
        self.assertEqual(res.omitted_lines, [])
        text = res.data.decode()
        for v in ALL_SECRET_VALUES:
            self.assertNotIn(v, text)
        self.assertEqual(rescan_file(res.data, "s.jsonl", self.r), [])

    def test_duplicate_keys_are_not_copied_verbatim(self):
        for raw in (b'{"creator_user_id":"user-REALID42","creator_user_id":""}\n',
                    b'{"creator_user_id":"","creator_user_id":"user-REALID42"}\n',
                    b'{"password":"x","password":"REALID42pw"}\n'):
            res = process_jsonl(raw, "s.jsonl", self.r)
            self.assertNotIn(b"REALID42", res.data)
            self.assertEqual(res.omitted_lines, [(1, "duplicate_keys")])
            self.assertEqual(rescan_file(res.data, "s.jsonl", self.r), [])

    def test_lone_surrogate_does_not_crash(self):
        raw = ('{"t": "\\ud83d ' + SECRETS["email"] + '"}\n').encode()
        res = process_jsonl(raw, "s.jsonl", self.r)
        self.assertNotIn(SECRETS["email"].encode(), res.data)
        json.loads(res.data)

    def test_env_style_password_names(self):
        for text in ("PGPASSWORD=s3cr3tpw", "DB_PASS=s3cr3tpw", "export MYSQL_PWD='s3cr3tpw'"):
            out, hits = self.r.redact_text(text)
            self.assertNotIn("s3cr3tpw", out, text)
        for text in ("mysql -u root -p's3cr3tpw' app", "sshpass -p s3cr3tpw ssh host"):
            out, _ = self.r.redact_text(text)
            self.assertNotIn("s3cr3tpw", out, text)
        for text in ("BYPASS=enabled", "COMPASS: north-east", "SKIP_BYPASS=enabled"):
            out, hits = self.r.redact_text(text)
            self.assertEqual(hits, [], text)

    def test_findings_never_contain_values(self):
        raw = (json.dumps({"t": f"{SECRETS['openai']} {SECRETS['email']}"}) + "\n").encode()
        res = process_jsonl(raw, "s.jsonl", self.r)
        dumped = json.dumps([f.to_dict() for f in res.locations])
        for v in ALL_SECRET_VALUES:
            self.assertNotIn(v, dumped)

    def test_rescan_flags_unredacted_content_without_echoing_it(self):
        raw = (json.dumps({"t": SECRETS["openai"]}) + "\n").encode()
        problems = rescan_file(raw, "s.jsonl", self.r)
        self.assertTrue(problems)
        self.assertNotIn(SECRETS["openai"], " ".join(problems))


class CredentialNamesTest(unittest.TestCase):
    def test_blocklist(self):
        from session_exporter.discovery import is_credential_file
        for name in ("auth.json", ".credentials.json", "credentials", ".env", ".env.local",
                     "prod.env", ".envrc", ".pgpass", "server.pem", "id_ed25519",
                     "service-account-prod.json", "client_secret_123.json", "state_5.sqlite",
                     "secrets.yaml", ".dockerconfigjson"):
            self.assertTrue(is_credential_file(name), name)
        for name in ("app.py", "README.md", "agent-1.jsonl", "environment.yml"):
            self.assertFalse(is_credential_file(name), name)


class OtherFilesTest(unittest.TestCase):
    def test_text_binary_and_json(self):
        r = redactor()
        res = process_text(f"token: {SECRETS['github']}\n".encode(), "x.txt", r)
        self.assertNotIn(SECRETS["github"], res.data.decode())
        self.assertIsNone(process_text(b"\x00\x01binary", "x.bin", r).data)
        self.assertIsNone(process_text(b"\xff\xfe\xfa", "x.txt", r).data)
        res = process_file(json.dumps({"password": "x1234"}).encode(), "m.json", r)
        self.assertNotIn("x1234", res.data.decode())
        self.assertIsNone(process_file(b"{not json", "m.json", r).data)


if __name__ == "__main__":
    unittest.main()
