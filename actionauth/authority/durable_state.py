"""Durable, shared, TTL-aware replay state for the delegation authority and Resource Server.

Why this exists
---------------
``InProcessAuthority``, ``OAuthAuthority``, and ``JwtResourceServer`` each enforce
single-use ("one signature = one credential = one execution") with an
**in-process** set:

  - ``_consumed_signatures`` — mint-time guard: the same signed RAR payload
    cannot be exchanged for two credentials.
  - ``_consumed``            — consume-time guard: a minted credential's
    ``jti`` cannot be consumed twice.

Both are thread-safe *within one process* but (a) vanish on restart and (b)
are **not shared across processes**. The card's #1 known trap is exactly this:
``stateless=True`` does not make delegation authority replay state safe across replicas. Two
bridge replicas, or a restart inside the 5-minute TTL, each start with an
empty set, so a captured-but-not-yet-replayed signed payload or credential can
be re-minted / re-consumed.

``DurableReplayState`` is the shared substrate that closes that surface: a
SQLite file that every replica and every post-restart process opens. The
single-use decision is made **atomically** by the database (``INSERT OR
IGNORE`` enforcing the primary key), not by a check-then-set in Python, so two
replicas racing to present the same payload cannot both win.

Two call sites, one table each
------------------------------
  - :meth:`claim_signature` — mint-time: returns ``True`` only for the *first*
    presentation of a signed payload; ``False`` for any later presentation.
    This is the load-bearing **cross-replica** guard: a signed payload minted
    on replica A is rejected on replica B (and after a restart) because the
    record is shared.
  - :meth:`claim_jti` — consume-time: returns ``True`` only for the *first*
    consume of a credential ``jti``; ``False`` for any later consume. This is
    the load-bearing guard at the **Resource Server**, which validates JWTs
    independently (no ``_issued`` table of its own), so its consumed-jti set is
    its *only* single-use backstop; making it shared means a JWT consumed on
    RS-A is rejected on RS-B and after an RS restart.

What "TTL-aware" means here
---------------------------
Each record stores ``expired_at``:

  - a *signature* record's ``expired_at`` is the **signed payload's** ``exp``
    (the re-mint window);
  - a *jti* record's ``expired_at`` is the **credential's** ``exp`` (the
    replay window).

A consumed record blocks a repeat presentation **for the whole window and
beyond** — exactly the in-memory set's "once consumed, always a replay"
semantics, but now durable and shared. The window value matters for two
reasons:

  1. ``purge_expired`` uses it to reclaim old rows (see below);
  2. it documents the security boundary: the record is *guaranteed* to block
     for at least the credential's validity window, which is all the threat
     model needs.

**Why "block beyond the window" is safe, not a bug.** In every consumer the
*expiry check runs before the replay claim*: an expired signed payload is
rejected by ``CredentialExpired`` at ``mint`` before it reaches
``claim_signature``; an expired credential is rejected by
``CredentialExpired`` at ``consume`` / the RS before it reaches
``claim_jti``. So a permanently-recorded key can never cause a *valid*
re-presentation to be falsely reported as a replay — there is no valid
re-presentation of an expired key to begin with.

**Purge is explicit, never automatic.** :meth:`purge_expired` drops rows whose
window has closed, but it is a housekeeping call the operator/deployment makes
on a schedule — the library never calls it on its own. Keeping it explicit
avoids a clock-skew hole: if replicas disagree on the wall clock, automatic
purge at ``expired_at`` could drop a record that a lagging replica still needs
to block on. The in-memory baseline grows unbounded for the same reason it
never prunes; the durable version offers the operator a safe way to reclaim
space without weakening the window guarantee.

Stdlib-only (``sqlite3`` + ``threading``) and transport-agnostic: the file is
the shared medium. In a real deployment the file lives on shared storage; a
Redis/Postgres backend can be swapped in behind the same method contract.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from collections.abc import Callable
from typing import TypeGuard


def _is_conn(x: object) -> TypeGuard[sqlite3.Connection]:
    return isinstance(x, sqlite3.Connection)


__all__ = ["DurableReplayState"]


_SCHEMA = """
CREATE TABLE IF NOT EXISTS consumed_signatures (
    sig_hash   TEXT PRIMARY KEY,
    minted_at  REAL NOT NULL,
    expired_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS consumed_signatures_expired
    ON consumed_signatures (expired_at);
CREATE TABLE IF NOT EXISTS consumed_jtis (
    jti         TEXT PRIMARY KEY,
    consumed_at REAL NOT NULL,
    expired_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS consumed_jtis_expired
    ON consumed_jtis (expired_at);
CREATE TABLE IF NOT EXISTS issued_jtis (
    jti         TEXT PRIMARY KEY,
    issued_at   REAL NOT NULL,
    expired_at  REAL NOT NULL,
    value       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS issued_jtis_expired
    ON issued_jtis (expired_at);
"""


class DurableReplayState:
    """A shared, durable, TTL-aware single-use store (see module docstring).

    Construction
    ------------
    Pass either a filesystem path (opened with WAL so a second replica's
    reader does not block the writer — the cross-process case) or an existing
    ``sqlite3.Connection`` (used by tests that want several state objects to
    share one in-memory database within a single process).

    Note: ``:memory:`` is single-process by definition — a *second*
    ``sqlite3.connect(":memory:")`` is a brand-new empty database. To exercise
    genuine cross-connection sharing, pass a temp **file** path.

    Parameters
    ----------
    path_or_conn:
        A path string, ``":memory:"``, or an existing ``sqlite3.Connection``.
    clock:
        A zero-arg callable returning a float "now" in epoch seconds.
        Injectable so tests can advance time without sleeping. Defaults to
        ``time.time``.
    """

    def __init__(
        self,
        path_or_conn: str | sqlite3.Connection,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        if _is_conn(path_or_conn):
            # Caller-supplied connection: the caller owns its lifetime.
            self._owns_conn = False
            self._conn = path_or_conn
        else:
            self._owns_conn = True
            path_str = str(path_or_conn)  # str here; _is_conn guarded the other arm
            # timeout= is the busy-wait (seconds) on a locked DB — the
            # cross-process case: a second replica hitting the file while the
            # first holds the write lock waits rather than erroring.
            conn = sqlite3.connect(path_str, check_same_thread=False, timeout=30.0)
            if path_str != ":memory:":
                # WAL lets a second replica read while the first writes — the
                # cross-process case. :memory: ignores WAL; leave it alone.
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

    def __enter__(self) -> "DurableReplayState":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # ── signature (mint-time) guard ───────────────────────────────────────

    def claim_signature(self, sig_hash: str, *, expired_at: float) -> bool:
        """Atomically record a signed payload as exchanged.

        Returns ``True`` only for the *first* presentation of ``sig_hash``;
        ``False`` for any later presentation (a replay). The record blocks for
        the whole window and beyond (safe: an expired payload is rejected by
        ``CredentialExpired`` at mint before it ever reaches this guard).
        """
        now = self._clock()
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO consumed_signatures "
                    "(sig_hash, minted_at, expired_at) VALUES (?, ?, ?)",
                    (sig_hash, now, expired_at),
                )
                return cur.rowcount == 1

    def is_signature_consumed(self, sig_hash: str) -> bool:
        """True if ``sig_hash`` has a record (was claimed), regardless of window.

        Mirrors :meth:`claim_signature`'s permanent "once exchanged, always a
        replay" semantics. Used for audit/observability and for the delegation authority's
        exception-ordering pre-check (report replay before drift); the
        load-bearing atomic decision is made by :meth:`claim_signature` at mint
        time. The record's ``expired_at`` is only for :meth:`purge_expired`
        housekeeping — a present record still blocks a re-presentation.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM consumed_signatures WHERE sig_hash = ?",
                (sig_hash,),
            ).fetchone()
        return row is not None

    # ── jti (consume-time) guard ──────────────────────────────────────────

    def claim_jti(self, jti: str, *, expired_at: float) -> bool:
        """Atomically record a credential ``jti`` as consumed.

        Returns ``True`` only for the *first* consume of ``jti``; ``False`` for
        any later consume (a replay). Same window/beyond semantics as
        :meth:`claim_signature`; an expired credential is rejected by
        ``CredentialExpired`` before it reaches this guard.
        """
        now = self._clock()
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO consumed_jtis "
                    "(jti, consumed_at, expired_at) VALUES (?, ?, ?)",
                    (jti, now, expired_at),
                )
                return cur.rowcount == 1

    def is_jti_consumed(self, jti: str) -> bool:
        """True if ``jti`` has a record (was consumed), regardless of window.

        Mirrors :meth:`claim_jti`'s permanent "once consumed, always a replay"
        semantics. Used for audit/observability and for the delegation authority/RS
        exception-ordering pre-check (report replay before drift); the
        load-bearing atomic decision is made by :meth:`claim_jti` at consume
        time. The record's ``expired_at`` is only for :meth:`purge_expired`
        housekeeping — a present record still blocks a re-consume.
        """
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM consumed_jtis WHERE jti = ?",
                (jti,),
            ).fetchone()
        return row is not None

    # ── Tier-1 issuance record (C4: _issued migrated into the backend) ────
    #
    # A mint writes one row: the issuance record (``command`` / ``args`` /
    # ``exp``) as JSON in ``value``, plus its validity window. The window is
    # the same ``ttl_s`` window the credential's own consume row uses: once
    # the credential's ``exp`` has passed the issuance record can no longer
    # be consulted (the credential is already expired), so the record never
    # outlives the credential it documents.

    def set_issued(self, jti: str, *, command: str, args: dict,
                   exp: int, expired_at: float) -> bool:
        """Atomically record a Tier-1 issuance (mint).

        ``True`` only for the first writer of ``jti`` (INSERT OR IGNORE);
        ``False`` when the record already exists — a concurrent double-mint
        whose second writer raced past ``claim_signature`` cannot
        overwrite the first record.
        """
        value = json.dumps({"command": command, "args": args, "exp": exp})
        now = self._clock()
        with self._lock:
            with self._conn:
                cur = self._conn.execute(
                    "INSERT OR IGNORE INTO issued_jtis "
                    "(jti, issued_at, expired_at, value) VALUES (?, ?, ?, ?)",
                    (jti, now, expired_at, value),
                )
                return cur.rowcount == 1

    def get_issued(self, jti: str) -> tuple[str, dict, int] | None:
        """Return the ``(command, args, exp)`` issuance record for ``jti``,
        or ``None`` if unknown or expired."""
        now = self._clock()
        with self._lock:
            row = self._conn.execute(
                "SELECT value FROM issued_jtis WHERE jti = ? AND expired_at > ?",
                (jti, now),
            ).fetchone()
        if row is None:
            return None
        rec = json.loads(row[0])
        return (rec["command"], rec["args"], rec["exp"])

    # ── housekeeping ──────────────────────────────────────────────────────

    def purge_expired(self) -> int:
        """Delete rows whose window has closed. Returns the count purged.

        **Explicit housekeeping only — never called automatically.** Pure
        memory reclamation: a closed window no longer blocks anything (the
        expiry check in every consumer runs first), so dropping the row
        changes no security decision *on the purging replica*. Callers running
        this across a fleet should account for cross-replica clock skew
        (purge only rows comfortably past their window).
        """
        now = self._clock()
        with self._lock:
            with self._conn:
                c1 = self._conn.execute(
                    "DELETE FROM consumed_signatures WHERE expired_at <= ?", (now,)
                )
                c2 = self._conn.execute(
                    "DELETE FROM consumed_jtis WHERE expired_at <= ?", (now,)
                )
                c3 = self._conn.execute(
                    "DELETE FROM issued_jtis WHERE expired_at <= ?", (now,)
                )
                return c1.rowcount + c2.rowcount + c3.rowcount
