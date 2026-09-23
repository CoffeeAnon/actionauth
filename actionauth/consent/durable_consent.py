"""Durable, shared, TTL-aware consent-session store.

Why this exists
---------------
The in-memory :class:`actionauth.consent.url_mode.ConsentStore` is
**single-process** by design: its ``_requests`` dict vanishes on a bridge
restart and is not visible to a second replica. In the single-agent MCP
gate a retried ``tools/call`` self-correlates to the same deterministic
consent ``session_id`` — if the bridge restarts mid-approval, or the
consent page is served by one replica and the submit by another, the
pending session is lost and the human has to start the approval over
(with the deterministic id, a silent *re-elicitation* instead of an
error).

:class:`DurableConsentStore` is the shared substrate that closes that
surface: a SQLite file that every replica and every post-restart process
opens. It uses the same stdlib-only (``sqlite3`` + ``threading``), WAL,
single-file pattern as :mod:`actionauth.authority.durable_state`.

The single-winner decision is made **atomically** by the database
(``UPDATE ... WHERE status='pending'``), not by a check-then-set in
Python, so two replicas racing to submit/deny the same session cannot
both win. Exactly one submit wins; exactly one deny wins; a deny after
a submit (or vice versa) is a no-op that returns ``False``.

TTL
---
Each session stores ``expired_at = created_at + ttl_seconds``. A
session whose window has closed is treated as if it never existed:
:py:meth:`get` returns ``None`` and the submit/deny CAS fails (the
``expired_at > now`` guard in the ``UPDATE``), so a stale session can
never be approved after the fact. :py:meth:`purge_expired` drops those
rows for housekeeping — explicit, never automatic (same clock-skew
rationale as :mod:`actionauth.authority.durable_state`).

API compatibility with :class:`actionauth.consent.url_mode.ConsentStore`
---------------------------------------------------------------------
The public surface is ``create`` / ``get`` / ``submit_signed`` /
``deny`` — a subset of the in-memory store's, with the same signatures
and the same semantics:

  - ``create`` is idempotent: a second ``create`` for an existing
    ``session_id`` returns the existing request (``INSERT OR IGNORE``),
    mirroring the in-memory store's "retried create returns the
    existing request" contract.
  - ``get`` returns a :class:`actionauth.consent.url_mode.ConsentRequest`
    (or ``None``) so the Starlette handlers in ``url_mode.py`` work
    unmodified.
  - ``submit_signed`` / ``deny`` return ``True`` only for the single
    winner of the pending→terminal transition.

The in-memory store's ``create`` returns the *same object* to repeated
callers (aliasing); this store returns a fresh ``ConsentRequest`` per
call because the database is the source of truth — callers must not
mutate the returned object and expect the mutation to persist (and the
Starlette handlers never do).

A production deployment would additionally need CSRF protection on the
submit endpoint and user authentication on the consent page; those are
HTTP-layer concerns outside this store's scope (see the module
docstring of ``actionauth.consent.url_mode``).
"""
from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
import types
from collections.abc import Callable
from typing import TypeGuard

from actionauth.consent.url_mode import ConsentRequest, ProposedAction

__all__ = ["DurableConsentStore"]


def _json_default(obj: object) -> object:
    """Serialisation fallback for non-JSON-serialisable args values.

    ``ProposedAction.create`` already unwraps ``MappingProxyType`` to a
    plain dict, but a defensive default keeps a future exotic value from
    crashing the store with a raw ``TypeError``.
    """
    if isinstance(obj, dict):
        return dict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _is_conn(x: object) -> TypeGuard[sqlite3.Connection]:
    return isinstance(x, sqlite3.Connection)


_STATUS_PENDING = "pending"
_STATUS_SUBMITTED = "submitted"
_STATUS_DENIED = "denied"


_SCHEMA = """
CREATE TABLE IF NOT EXISTS consent_sessions (
    session_id        TEXT PRIMARY KEY,
    command           TEXT NOT NULL,
    args_json         TEXT NOT NULL,
    rar_type          TEXT NOT NULL,
    approver_id       TEXT NOT NULL,
    binding_message   TEXT NOT NULL,
    status            TEXT NOT NULL,
    created_at        REAL NOT NULL,
    expires_at        REAL NOT NULL,
    signed_payload_json TEXT
);
CREATE INDEX IF NOT EXISTS consent_sessions_expires
    ON consent_sessions (expires_at);
"""


def _row_to_request(row) -> ConsentRequest:
    """Reconstruct a ``ConsentRequest`` from a stored row.

    Uses positional access so it works with or without a
    ``row_factory`` set on the connection (the existing
    :mod:`actionauth.authority.durable_state` module does the same: callers
    may supply their own ``sqlite3.Connection`` that hasn't had
    ``row_factory`` configured).

    Column order (matches ``_SCHEMA``):
        0  session_id        5  binding_message    9  signed_payload_json
        1  command           6  status
        2  args_json         7  created_at
        3  rar_type          8  expires_at
        4  approver_id

    ``signed_payload`` is ``None`` unless the row's status is
    ``submitted``; ``denied`` mirrors the in-memory store's boolean.
    """
    (
        session_id,
        command,
        args_json,
        rar_type,
        approver_id,
        binding_message,
        status,
        created_at,
        _expires_at,
        signed_payload_json,
    ) = row
    action = ProposedAction(
        session_id=session_id,
        command=command,
        # Re-wrap the decoded dict in a read-only proxy so the returned
        # request is structurally immutable, exactly like the in-memory
        # store's ``ProposedAction.create`` produces.
        args=types.MappingProxyType(json.loads(args_json)),
        rar_type=rar_type,
        approver_id=approver_id,
        binding_message=binding_message,
        created_at=created_at,
    )
    signed_payload = None
    if status == _STATUS_SUBMITTED and signed_payload_json is not None:
        signed_payload = json.loads(signed_payload_json)
    return ConsentRequest(
        action=action,
        signed_payload=signed_payload,
        denied=(status == _STATUS_DENIED),
    )


class DurableConsentStore:
    """A shared, durable, TTL-aware consent-session store.

    Construction
    ------------
    Pass either a filesystem path (opened with WAL so a second replica's
    reader does not block the writer — the cross-process case) or an
    existing ``sqlite3.Connection`` (used by tests that want several
    stores to share one in-memory database within a single process).

    Note: ``:memory:`` is single-process by definition — a *second*
    ``sqlite3.connect(":memory:")`` is a brand-new empty database. To
    exercise genuine cross-connection sharing, pass a temp **file** path.

    Parameters
    ----------
    path_or_conn:
        A path string, ``":memory:"``, or an existing ``sqlite3.Connection``.
    ttl_seconds:
        Per-session validity window (default 300 s — the "valid for 5
        minutes" the consent page promises the human). ``expired_at =
        created_at + ttl_seconds``.
    clock:
        A zero-arg callable returning a float "now" in epoch seconds.
        Injectable so tests can advance time without sleeping. Defaults
        to ``time.time``.
    """

    def __init__(
        self,
        path_or_conn: str | sqlite3.Connection,
        *,
        ttl_seconds: float = 300.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be > 0")
        self._clock = clock
        self._ttl = float(ttl_seconds)
        self._lock = threading.Lock()
        if _is_conn(path_or_conn):
            # Caller-supplied connection: the caller owns its lifetime.
            self._owns_conn = False
            self._conn = path_or_conn
        else:
            self._owns_conn = True
            path_str = str(path_or_conn)  # str here; _is_conn guarded the other arm
            conn = sqlite3.connect(path_str, check_same_thread=False, timeout=30.0)
            conn.row_factory = sqlite3.Row
            if path_str != ":memory:":
                # WAL lets a second replica read while the first writes.
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA synchronous=NORMAL")
            self._conn = conn
        with self._lock:
            with self._conn:
                self._conn.executescript(_SCHEMA)

    # ── lifecycle ─────────────────────────────────────────────────────────

    def close(self) -> None:
        """Close the underlying connection if we opened it. No-op otherwise."""
        if self._owns_conn:
            with self._lock:
                self._conn.close()

    def __enter__(self) -> "DurableConsentStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── session lifecycle ─────────────────────────────────────────────────

    def create(
        self,
        *,
        command: str,
        args: dict,
        rar_type: str,
        approver_id: str,
        binding_message: str,
        session_id: str | None = None,
    ) -> ConsentRequest:
        """Create (or return the existing) consent session.

        Mirrors :meth:`actionauth.consent.url_mode.ConsentStore.create`:
        ``session_id`` defaults to a fresh random token; a ``create`` for
        an id that already exists is idempotent and returns the existing
        request rather than overwriting it (``INSERT OR IGNORE``).

        The ``url`` the human is sent to is a transport concern of the
        HTTP layer that built the link — it is not persisted here; this
        store is the *state* substrate for the pending session.

        ``created_at`` is stamped from the injected clock, and
        ``expires_at = created_at + ttl_seconds``.
        """
        sid = session_id or secrets.token_urlsafe(16)
        now = self._clock()
        args_json = json.dumps(args, sort_keys=True, default=_json_default)
        with self._lock:
            with self._conn:
                # A deterministic id can outlive its TTL: the old row then
                # blocks INSERT OR IGNORE forever and the flow wedges
                # (create -> get -> None -> RuntimeError on every retry).
                # An *expired* pending or submitted row is no longer
                # actionable (get() already treats it as absent; submit/deny
                # CAS refuse it), so resetting it to a fresh session is
                # safe. Expired *denied* rows are kept: a refusal is a
                # human decision and must not be silently re-proposed.
                # In-window rows of any status are untouched (idempotent
                # create keeps the original action; submitted/denied rows
                # still short-circuit via OR IGNORE).
                self._conn.execute(
                    "DELETE FROM consent_sessions "
                    "WHERE session_id = ? AND status IN (?, ?) "
                    "AND created_at + ? < ?",
                    (sid, _STATUS_PENDING, _STATUS_SUBMITTED, self._ttl, now),
                )
                self._conn.execute(
                    "INSERT OR IGNORE INTO consent_sessions "
                    "(session_id, command, args_json, rar_type, approver_id, "
                    " binding_message, status, created_at, expires_at, "
                    " signed_payload_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)",
                    (
                        sid,
                        command,
                        args_json,
                        rar_type,
                        approver_id,
                        binding_message,
                        _STATUS_PENDING,
                        now,
                        now + self._ttl,
                    ),
                )
        # Fetch-then-build: the row exists now (either just inserted or
        # pre-existing); reconstruct the request from it.
        req = self.get(sid)
        if req is None:
            # Can only happen if the row was created *just now* with a
            # ttl that is already in the past (ttl <= 0 is rejected in
            # __init__, so this is a clock-rewind artefact) — surface it
            # rather than returning a None the caller cannot handle.
            raise RuntimeError(
                f"consent session {sid!r} was created but is already expired"
            )
        return req

    def get(self, session_id: str) -> ConsentRequest | None:
        """Return the consent request for ``session_id``.

        ``None`` if the session is unknown **or** its validity window has
        closed (``expires_at < now``) — an expired session is treated as
        if it never existed, so the consent page 404s and the poll
        endpoint reports "unknown session" after the TTL.
        """
        now = self._clock()
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM consent_sessions WHERE session_id = ? AND expires_at > ?",
                (session_id, now),
            ).fetchone()
        if row is None:
            return None
        return _row_to_request(row)

    def submit_signed(self, session_id: str, signed_payload: dict) -> bool:
        """Atomically transition a pending session to submitted.

        ``True`` only for the *single* winner of the
        pending→submitted CAS; ``False`` if the session is unknown,
        already submitted, already denied, or expired. The CAS is the
        ``UPDATE ... WHERE status='pending' AND expires_at > now`` —
        the database is the single-winner authority, not Python.
        """
        payload_json = json.dumps(signed_payload, sort_keys=True)
        now = self._clock()
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "UPDATE consent_sessions "
                    "SET status = ?, signed_payload_json = ? "
                    "WHERE session_id = ? AND status = ? AND expires_at > ?",
                    (
                        _STATUS_SUBMITTED,
                        payload_json,
                        session_id,
                        _STATUS_PENDING,
                        now,
                    ),
                )
                return cur.rowcount == 1

    def deny(self, session_id: str) -> bool:
        """Atomically transition a pending session to denied.

        ``True`` only for the *single* winner of the pending→denied CAS;
        ``False`` if the session is unknown, already submitted, already
        denied, or expired.
        """
        now = self._clock()
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "UPDATE consent_sessions "
                    "SET status = ? "
                    "WHERE session_id = ? AND status = ? AND expires_at > ?",
                    (
                        _STATUS_DENIED,
                        session_id,
                        _STATUS_PENDING,
                        now,
                    ),
                )
                return cur.rowcount == 1

    # ── housekeeping ──────────────────────────────────────────────────────

    def purge_expired(self) -> int:
        """Delete rows whose window has closed. Returns the count purged.

        **Explicit housekeeping only — never called automatically.**
        Terminal-state rows (submitted/denied) are kept: they are the
        audit trail of what the human decided and are not replay
        surface. Only *pending* rows that have expired are reclaimed —
        an expired pending session is already invisible to
        :py:meth:`get` and inert in the submit/deny CAS, so dropping it
        changes no decision.
        """
        now = self._clock()
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "DELETE FROM consent_sessions "
                    "WHERE expires_at <= ? AND status = ?",
                    (now, _STATUS_PENDING),
                )
                return cur.rowcount
