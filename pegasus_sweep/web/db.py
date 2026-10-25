"""SQLite persistence for scan history.

Stores one row per scan; findings and snapshots are kept as JSON blobs so the
web layer can render any past scan without re-running the (slow) scan.

Thread-safety: a fresh sqlite3 connection is opened per operation (SQLite
connections are not shareable across threads, and Flask/agent paths run on
multiple threads). SQLite serializes writes at the file level, which is fine
for this low-write-rate store.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

from pegasus_sweep.core import settings

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    target      TEXT NOT NULL,          -- desktop | ios | android
    mode        TEXT NOT NULL,          -- agentless | agent | upload
    source_label TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    status      TEXT NOT NULL,          -- done | error | note
    message     TEXT NOT NULL DEFAULT '',
    summary_json TEXT NOT NULL DEFAULT '{}',
    snapshot_json TEXT NOT NULL DEFAULT '{}',
    findings_json TEXT NOT NULL DEFAULT '[]'
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanStore:
    def __init__(self, path: Path | None = None):
        self.path = Path(path or settings.BASE_DIR / "data" / "scans.db")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        # initialise schema with a throwaway connection (thread-safe)
        with self._conn() as c:
            c.executescript(_SCHEMA)

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def insert(self, *, target: str, mode: str, source_label: str = "",
               status: str, message: str = "",
               summary: dict[str, Any] | None = None,
               snapshot: dict[str, Any] | None = None,
               findings: list[dict[str, Any]] | None = None) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO scans
                   (target, mode, source_label, created_at, status, message,
                    summary_json, snapshot_json, findings_json)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (target, mode, source_label, _now(), status, message,
                 json.dumps(summary or {}, default=str),
                 json.dumps(snapshot or {}, default=str),
                 json.dumps(findings or [], default=str)),
            )
            return int(cur.lastrowid)

    def update(self, scan_id: int, *, status: str, message: str = "",
               summary: dict[str, Any] | None = None,
               snapshot: dict[str, Any] | None = None,
               findings: list[dict[str, Any]] | None = None) -> bool:
        with self._conn() as conn:
            cur = conn.execute(
                """UPDATE scans SET status=?, message=?,
                        summary_json=?, snapshot_json=?, findings_json=?
                   WHERE id=?""",
                (status, message,
                 json.dumps(summary or {}, default=str),
                 json.dumps(snapshot or {}, default=str),
                 json.dumps(findings or [], default=str), scan_id))
        return cur.rowcount > 0

    def get(self, scan_id: int) -> dict[str, Any] | None:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["summary"] = json.loads(d.pop("summary_json") or "{}")
        d["snapshot"] = json.loads(d.pop("snapshot_json") or "{}")
        d["findings"] = json.loads(d.pop("findings_json") or "[]")
        return d

    def recent(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["summary"] = json.loads(d.pop("summary_json") or "{}")
            d["findings"] = json.loads(d.pop("findings_json") or "[]")
            d.pop("snapshot_json", None)
            out.append(d)
        return out

    def delete(self, scan_id: int) -> bool:
        with self._conn() as conn:
            cur = conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
        return cur.rowcount > 0

    def counts_by_target(self) -> dict[str, int]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT target, COUNT(*) c FROM scans GROUP BY target").fetchall()
        return {r["target"]: r["c"] for r in rows}