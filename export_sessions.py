#!/usr/bin/env python3
"""Run the session exporter without installing it: python export_sessions.py --help"""

import sys

from session_exporter.cli import main

if __name__ == "__main__":
    sys.exit(main())
