"""
INTENTIONALLY VULNERABLE -- for testing the SAST engine only. Never deploy this.

Zip this file (see instructions) and upload it to /api/analyze. Bandit and
Semgrep should each flag several issues, giving you real findings on the very
first run.
"""

import sqlite3
import subprocess

# CWE-798: hardcoded credentials (Bandit B105/B106)
API_KEY = "sk_live_1234567890abcdef"
DB_PASSWORD = "admin123"


def get_user(username):
    conn = sqlite3.connect("app.db")
    cur = conn.cursor()
    # CWE-89: SQL injection via string formatting (Bandit B608 / Semgrep)
    query = "SELECT * FROM users WHERE name = '%s'" % username
    cur.execute(query)
    return cur.fetchall()


def run_command(user_input):
    # CWE-78: OS command injection via shell=True (Bandit B602)
    return subprocess.call("ping " + user_input, shell=True)


def calculate(expr):
    # CWE-95: eval on untrusted input (Bandit B307)
    return eval(expr)