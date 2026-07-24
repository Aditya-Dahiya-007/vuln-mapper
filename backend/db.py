"""
db.py -- tiny SQLite persistence layer for Vuln-Mapper.

One 'scans' table doubles as the job queue AND the history:
    status = 'running'  -> a job is in flight (a background thread is working)
    status = 'done'     -> finished, full result stored
    status = 'error'    -> failed, message stored

A fresh connection is opened per call, which keeps this safe to use from the
background worker threads without any shared-connection headaches.
"""

import datetime
import json
import os
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vulnmapper.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with _conn() as c:
        c.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id         TEXT PRIMARY KEY,
                kind       TEXT NOT NULL,      -- 'recon' | 'audit'
                label      TEXT,               -- target host or filename
                status     TEXT NOT NULL,      -- 'running' | 'done' | 'error'
                summary    TEXT,               -- small JSON for the list view
                result     TEXT,               -- full JSON result blob
                error      TEXT,               -- message if status='error'
                created_at TEXT NOT NULL
            )
            """
        )


def create_scan(kind: str, label: str) -> str:
    sid = uuid.uuid4().hex[:12]
    now = datetime.datetime.now().isoformat(timespec="seconds")
    with _conn() as c:
        c.execute(
            "INSERT INTO scans (id, kind, label, status, created_at) VALUES (?, ?, ?, ?, ?)",
            (sid, kind, label, "running", now),
        )
    return sid


def finish_scan(sid: str, result: Dict[str, Any], summary: Dict[str, Any]) -> None:
    with _conn() as c:
        c.execute(
            "UPDATE scans SET status='done', result=?, summary=? WHERE id=?",
            (json.dumps(result), json.dumps(summary), sid),
        )


def fail_scan(sid: str, error: Any) -> None:
    with _conn() as c:
        c.execute("UPDATE scans SET status='error', error=? WHERE id=?", (str(error), sid))


def get_scan(sid: str) -> Optional[Dict[str, Any]]:
    with _conn() as c:
        row = c.execute("SELECT * FROM scans WHERE id=?", (sid,)).fetchone()
    return _row_to_dict(row, include_result=True) if row else None


def set_summary(sid: str, summary: Dict[str, Any]) -> None:
    """Update just the summary blob (used to report live job progress)."""
    with _conn() as c:
        c.execute("UPDATE scans SET summary=? WHERE id=?", (json.dumps(summary), sid))


def list_scans(limit: int = 25) -> List[Dict[str, Any]]:
    # AI-remediated reports are derived artifacts, not scans, so keep them out
    # of the history list (they're still fetchable by id).
    with _conn() as c:
        rows = c.execute(
            "SELECT * FROM scans WHERE kind != 'ai_report' ORDER BY created_at DESC LIMIT ?",
            (int(limit),),
        ).fetchall()
    return [_row_to_dict(r, include_result=False) for r in rows]


def delete_scan(sid: str) -> None:
    with _conn() as c:
        c.execute("DELETE FROM scans WHERE id=?", (sid,))


def _row_to_dict(row: sqlite3.Row, include_result: bool) -> Dict[str, Any]:
    d: Dict[str, Any] = {
        "id": row["id"],
        "kind": row["kind"],
        "label": row["label"],
        "status": row["status"],
        "created_at": row["created_at"],
        "summary": json.loads(row["summary"]) if row["summary"] else None,
        "error": row["error"],
    }
    if include_result:
        d["result"] = json.loads(row["result"]) if row["result"] else None
    return d