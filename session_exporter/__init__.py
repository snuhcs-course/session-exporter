"""Export Codex CLI and Claude Code session histories for one repository.

Everything runs locally. Original session files are only ever opened for
reading; redacted copies are written to a private staging directory and then
packed into a ZIP archive after a final privacy re-scan and a review step.
"""

__version__ = "0.1.0"

DISCLAIMER = (
    "Automated redaction is best-effort. It cannot guarantee that all "
    "sensitive information (secrets, credentials, personal data) has been "
    "removed. Review the exported files before sharing them."
)
