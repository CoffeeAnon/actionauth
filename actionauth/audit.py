"""Append-only SQLite audit log.

Records tool calls, approval grants/rejections, and errors. Used by the
MCP server (every request writes one row) and by the dispatcher tests.
Stdlib-only — no external dependencies.
"""
from __future__ import annotations

import logging
import os
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, UTC

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS audit_log (
    id             INTEGER PRIMARY KEY,
    ts             TEXT         NOT NULL,
    thread_id      TEXT         NOT NULL,
    tenant_id      TEXT         NOT NULL,
    kind           TEXT         NOT NULL,
    node           TEXT,
    tool_name      TEXT,
    tool_args      TEXT,
    result_snippet TEXT,
    latency_ms     INTEGER,
    token_usage    TEXT,
    actor          TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_thread_ts ON audit_log(thread_id, ts);
CREATE INDEX IF NOT EXISTS audit_log_tenant_ts ON audit_log(tenant_id, ts);
"""

_INSERT = """
INSERT INTO audit_log
    (ts, thread_id, tenant_id, kind, node, tool_name, tool_args,
     result_snippet, latency_ms, token_usage, actor)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class AuditRow:
    thread_id: str
    tenant_id: str
    kind: str  # llm_call|tool_call|tool_result|approval_requested|approval_granted|approval_rejected|error
    ts: str = field(default_factory=_now_iso)
    node: str | None = None
    tool_name: str | None = None
    tool_args: str | None = None
    result_snippet: str | None = None
    latency_ms: int | None = None
    token_usage: str | None = None
    actor: str = "agent"


class AuditSink:
    """Append-only SQLite audit log. write() never raises; __init__ raises on connection failure."""

    # Log on first failure and then every N failures to avoid log spam.
    _LOG_INTERVAL = 50

    def __init__(self, db_path: str | sqlite3.Connection):
        if isinstance(db_path, sqlite3.Connection):
            self._conn = db_path
        else:
            if db_path not in (":memory:",):
                os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
            self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._consecutive_failures = 0

    def write(self, row: AuditRow) -> None:
        try:
            self._conn.execute(
                _INSERT,
                (
                    row.ts, row.thread_id, row.tenant_id, row.kind, row.node,
                    row.tool_name, row.tool_args, row.result_snippet,
                    row.latency_ms, row.token_usage, row.actor,
                ),
            )
            self._conn.commit()
            self._consecutive_failures = 0
        except Exception as exc:
            self._consecutive_failures += 1
            if self._consecutive_failures == 1 or self._consecutive_failures % self._LOG_INTERVAL == 0:
                logger.error(
                    "AuditSink.write failed (%d consecutive failures): %s",
                    self._consecutive_failures, exc,
                )

