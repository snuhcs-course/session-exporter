"""Builders for synthetic Codex / Claude Code session fixtures.

The record shapes mirror fields verified in real session files (see
session_exporter/discovery.py); all content is synthetic. Fake secrets are
assembled at runtime so this file itself does not look like it leaks keys.
"""

import json
import os
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from session_exporter.paths import claude_project_dirname  # noqa: E402

SECRETS = {
    "openai": "sk-" + "proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z",
    "anthropic": "sk-" + "ant-" + "api03-" + "Zz9Yy8Xx7Ww6Vv5Uu4Tt3Ss2",
    "github": "gh" + "p_" + "aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2",
    "aws_id": "AK" + "IA" + "QWERTYUIOPASDFGH",
    "password": "Hunter2" + "!secret",
    "private_key_body": "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" + "SYNTHETICKEYDATA",
    "email": "kim.student" + "@" + "snu-mail.ac.kr",
    "phone": "010-" + "1234-" + "5678",
    "rrn": "990101-" + "1234567",
    "card": "4111 1111 " + "1111 1111",
    "jwt": "eyJ" + "hbGciOiJIUzI1NiJ9" + "." + "eyJ" + "zdWIiOiIxMjM0NTY3ODkwIn0" + "." + "SflKxwRJSMeKKF2QT4fw",
    "student_name": "Hong" + " Gildong",
}
PRIVATE_KEY = ("-----BEGIN RSA PRIVATE KEY-----\n" + SECRETS["private_key_body"]
               + "\n-----END RSA PRIVATE KEY-----")

ALL_SECRET_VALUES = [v for k, v in SECRETS.items() if k != "private_key_body"] + [
    SECRETS["private_key_body"]]


def write_jsonl(path: Path, records, raw_suffix: bytes = b"") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as fh:
        for r in records:
            if isinstance(r, bytes):
                fh.write(r + b"\n")
            else:
                fh.write(json.dumps(r).encode("utf-8") + b"\n")
        fh.write(raw_suffix)
    return path


# ---------------------------------------------------------------- Codex ----

def codex_meta(sid, cwd, ts, parent=None):
    payload = {"id": sid, "timestamp": ts, "cwd": cwd, "originator": "codex_cli_rs",
               "cli_version": "0.144.3", "source": "cli", "model_provider": "openai",
               "creator_user_id": "user-SYNTH0001", "creator_account_id": "acct-SYNTH0002"}
    if parent:
        payload["parent_thread_id"] = parent
    return {"timestamp": ts, "type": "session_meta", "payload": payload}


def codex_turn(cwd, ts):
    return {"timestamp": ts, "type": "turn_context",
            "payload": {"cwd": cwd, "model": "gpt-5", "approval_policy": "on-request"}}


def codex_message(role, text, ts):
    kind = "input_text" if role == "user" else "output_text"
    return {"timestamp": ts, "type": "response_item",
            "payload": {"type": "message", "role": role, "content": [{"type": kind, "text": text}]}}


def codex_tool_call(command, output, ts, call_id="call_1"):
    return [
        {"timestamp": ts, "type": "response_item",
         "payload": {"type": "function_call", "name": "shell", "call_id": call_id,
                     "arguments": json.dumps({"command": ["bash", "-lc", command]})}},
        {"timestamp": ts, "type": "response_item",
         "payload": {"type": "function_call_output", "call_id": call_id, "output": output}},
    ]


def codex_rollout(home: Path, sid: str, start_ts: str, records, raw_suffix: bytes = b"",
                  archived: bool = False) -> Path:
    y, m, d = start_ts[:4], start_ts[5:7], start_ts[8:10]
    stamp = start_ts[:19].replace(":", "-")
    base = home / ("archived_sessions" if archived else Path("sessions", y, m, d))
    return write_jsonl(base / f"rollout-{stamp}-{sid}.jsonl", records, raw_suffix)


# ---------------------------------------------------------- Claude Code ----

def claude_record(rtype, sid, cwd, ts, message=None, **extra):
    r = {"parentUuid": None, "isSidechain": False, "userType": "external", "cwd": cwd,
         "sessionId": sid, "version": "2.1.0", "gitBranch": "main", "type": rtype,
         "uuid": str(uuid.uuid4()), "timestamp": ts}
    if message is not None:
        r["message"] = message
    r.update(extra)
    return r


def claude_user(sid, cwd, ts, text):
    return claude_record("user", sid, cwd, ts, {"role": "user", "content": text})


def claude_tool_use(sid, cwd, ts, name, tool_input, tool_id="toolu_1"):
    return claude_record("assistant", sid, cwd, ts, {
        "role": "assistant", "model": "claude-sonnet-5-5",
        "content": [{"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}]})


def claude_tool_result(sid, cwd, ts, content, tool_id="toolu_1"):
    return claude_record("user", sid, cwd, ts, {
        "role": "user",
        "content": [{"type": "tool_result", "tool_use_id": tool_id, "content": content}]})


def claude_snapshot(ts, backups):
    """backups: {relative_key: (backupFileName, realParentDir)}"""
    tracked = {k: {"backupFileName": name, "version": 1, "backupTime": ts, "realParentDir": parent}
               for k, (name, parent) in backups.items()}
    return {"type": "file-history-snapshot", "messageId": str(uuid.uuid4()),
            "snapshot": {"messageId": str(uuid.uuid4()), "timestamp": ts,
                         "trackedFileBackups": tracked},
            "isSnapshotUpdate": False}


def claude_session(home: Path, sid: str, records, project_dir: str = None, cwd: str = None,
                   raw_suffix: bytes = b"") -> Path:
    project_dir = project_dir or claude_project_dirname(cwd)
    return write_jsonl(home / "projects" / project_dir / f"{sid}.jsonl", records, raw_suffix)


def snapshot_tree(root: Path) -> dict:
    """Map of every file under root -> (bytes, mtime_ns) for immutability checks."""
    out = {}
    for dirpath, _, files in os.walk(root):
        for f in files:
            p = Path(dirpath, f)
            st = p.stat()
            out[str(p)] = (p.read_bytes(), st.st_mtime_ns)
    return out
