"""Audit fidelity — every dispatch outcome writes the expected audit row(s).

The audit log is the tamper-evident record of who approved what and when.
If a write happens without an audit row, the property "HITL approvals are
auditable" breaks.
"""
import sqlite3

import pytest

from actionauth.audit import AuditRow, AuditSink


def _read_rows(db_path) -> list[dict]:
    with sqlite3.connect(str(db_path)) as con:
        con.row_factory = sqlite3.Row
        return [dict(r) for r in con.execute("SELECT * FROM audit_log ORDER BY id").fetchall()]


def test_audit_sink_writes_one_row_per_write(tmp_path):
    db_path = tmp_path / "audit.db"
    sink = AuditSink(str(db_path))

    sink.write(AuditRow(
        thread_id="tenant1:ctx-1",
        tenant_id="tenant1",
        kind="tool_call",
        tool_name="list-tasks",
        tool_args="{}",
        result_snippet="",
        actor="alice",
    ))
    sink.write(AuditRow(
        thread_id="tenant1:ctx-1",
        tenant_id="tenant1",
        kind="approval_granted",
        tool_name="delete-task",
        tool_args="{'task_id': 't-42'}",
        result_snippet="",
        actor="alice",
    ))

    rows = _read_rows(db_path)
    assert len(rows) == 2
    assert {r["kind"] for r in rows} == {"tool_call", "approval_granted"}
    delete_row = next(r for r in rows if r["kind"] == "approval_granted")
    assert delete_row["tool_name"] == "delete-task"
    assert delete_row["actor"] == "alice"
    assert "t-42" in delete_row["tool_args"]


def test_audit_sink_swallows_write_errors(tmp_path):
    """AuditSink.write never raises — it logs and increments a failure counter.
    This is a property the production paths depend on (audit writes are
    fire-and-forget alongside the actual tool execution)."""
    sink = AuditSink(str(tmp_path / "audit.db"))
    # Close the connection underneath the sink to force a write failure.
    sink._conn.close()
    # Should not raise:
    sink.write(AuditRow(thread_id="x", tenant_id="x", kind="tool_call"))
