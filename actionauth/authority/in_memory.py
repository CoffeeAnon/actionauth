"""In-memory StateBackend for single-process tests and in-memory deployments.

This module provides :class:`InMemoryStateBackend`, a thread-safe dict-backed
implementation of the :class:`~actionauth.authority.interface.StateBackend` protocol.

Why it exists
-------------
The reviewer's acceptance test (correction 2) simulates replica B "by a second
``StateBackend`` instance sharing the same underlying dict." ``InMemoryStateBackend``
is the backend that makes that test possible: construct two instances with the
same ``shared`` dict and they behave as two replicas of the same shared state.

It is also the default backend for single-process tests that do not need
durability or cross-process sharing — a lightweight alternative to
``DurableReplayState(":memory:")``.

Both ``InMemoryStateBackend`` and ``DurableReplayState`` satisfy the
``StateBackend`` protocol structurally (``typing.Protocol``); the delegation authority/RS
accept either via their ``durable_state`` parameter.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable


class InMemoryStateBackend:
    """Thread-safe, in-memory single-use store.

    Construction
    ------------
    Pass an optional ``shared`` dict to have two (or more) instances share the
    same backing store — this is the acceptance-test "replica B" pattern.
    Each internal table is a plain ``dict[str, float]`` mapping the key
    (``sig_hash`` or ``jti``) to its ``expired_at`` timestamp.

    ``clock`` is an injectable zero-arg callable returning a float "now" in
    epoch seconds, for tests that advance time without sleeping. Defaults to
    ``time.time``.

    Thread safety: every mutating operation acquires a single ``threading.Lock``.
    This is correct for single-process use; for cross-process sharing use
    ``DurableReplayState`` with a file path.
    """

    def __init__(
        self,
        *,
        shared: dict | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        # Two logical tables in one backing dict namespace.
        # _shared is the caller-provided dict (or a fresh {} if not given).
        # We store two sub-dicts inside it: "sigs" and "jtis".
        # This way two InMemoryStateBackend(shared=shared_dict) instances
        # share the same sigs and jtis tables.
        if shared is None:
            shared = {}
        self._shared = shared
        if "sigs" not in self._shared:
            self._shared["sigs"] = {}
        if "jtis" not in self._shared:
            self._shared["jtis"] = {}
        # issued: jti -> expired_at float; the issuance record itself
        # (command/args/exp) lives in "issued_records" keyed by jti.
        if "issued" not in self._shared:
            self._shared["issued"] = {}
        if "issued_records" not in self._shared:
            self._shared["issued_records"] = {}

    @property
    def _sigs(self) -> dict[str, float]:
        return self._shared["sigs"]

    @property
    def _jtis(self) -> dict[str, float]:
        return self._shared["jtis"]

    @property
    def _issued(self) -> dict[str, float]:
        return self._shared["issued"]

    @property
    def _issued_records(self) -> dict[str, tuple[str, dict, int]]:
        return self._shared["issued_records"]

    # ── signature (mint-time) guard ───────────────────────────────────────

    def claim_signature(self, sig_hash: str, *, expired_at: float) -> bool:
        """Atomically record a signed payload as exchanged.

        Returns ``True`` only for the *first* presentation of ``sig_hash``;
        ``False`` for any later presentation (a replay).
        """
        with self._lock:
            if sig_hash in self._sigs:
                return False
            self._sigs[sig_hash] = expired_at
            return True

    def is_signature_consumed(self, sig_hash: str) -> bool:
        """True if ``sig_hash`` has a record (was claimed), regardless of window."""
        with self._lock:
            return sig_hash in self._sigs

    # ── jti (consume-time) guard ──────────────────────────────────────────

    def claim_jti(self, jti: str, *, expired_at: float) -> bool:
        """Atomically record a credential ``jti`` as consumed.

        Returns ``True`` only for the *first* consume of ``jti``; ``False``
        for any later consume (a replay).
        """
        with self._lock:
            if jti in self._jtis:
                return False
            self._jtis[jti] = expired_at
            return True

    def is_jti_consumed(self, jti: str) -> bool:
        """True if ``jti`` has a record (was consumed), regardless of window."""
        with self._lock:
            return jti in self._jtis

    # ── Tier-1 issuance record ─────────────────────────────────────────────

    def set_issued(self, jti: str, *, command: str, args: dict,
                   exp: int, expired_at: float) -> bool:
        """Atomically record a Tier-1 issuance (mint).

        Returns ``True`` only for the *first* writer of ``jti``; ``False``
        when the record already exists (a concurrent double-mint is being
        rejected elsewhere in the authority).
        """
        record = (command, args, exp)
        with self._lock:
            if jti in self._issued:
                return False
            self._issued[jti] = expired_at
            self._issued_records[jti] = record
            return True

    def get_issued(self, jti: str) -> tuple[str, dict, int] | None:
        """Return the ``(command, args, exp)`` issuance record for ``jti``,
        or ``None`` if unknown or expired."""
        with self._lock:
            expired_at = self._issued.get(jti)
            if expired_at is None:
                return None
            if expired_at <= self._clock():
                return None
            return self._issued_records.get(jti)

    # ── housekeeping ──────────────────────────────────────────────────────

    def purge_expired(self) -> int:
        """Delete records whose window has closed. Returns the count purged.

        Explicit housekeeping only — never called automatically.
        """
        now = self._clock()
        purged = 0
        with self._lock:
            for table in (self._sigs, self._jtis, self._issued):
                expired = [k for k, exp in table.items() if exp <= now]
                for k in expired:
                    del table[k]
                    purged += 1
        return purged


# ── process-wide default backend (C3: close the silent per-process default) ──

_default_backend: InMemoryStateBackend | None = None
_default_backend_lock = threading.Lock()


def get_default_backend() -> InMemoryStateBackend:
    """Return the process-wide default :class:`InMemoryStateBackend`.

    Every default-constructed delegation authority / Resource Server in this process
    shares this one instance, so the three in-scope state categories
    (signed-payload replay, consumed-jti, Tier-1 issuance record) are
    consistent *across components* even when nothing is injected.

    This is NOT cross-process state: a second OS process gets its own
    singleton (a fresh dict), exactly like the old per-process sets. For
    cross-replica / restart durability the operator injects a
    :class:`~actionauth.authority.durable_state.DurableReplayState` built on a
    file on shared storage. The default exists so that a default
    deployment can no longer run in *component-local* state — the
    reviewer's NEGCTRL-1 (two default-constructed delegation authorities minting the same
    signed payload twice) now fails, because both authorities hit this same
    backend's ``claim_signature``.
    """
    global _default_backend
    with _default_backend_lock:
        if _default_backend is None:
            _default_backend = InMemoryStateBackend()
        return _default_backend


def reset_default_backend() -> None:
    """Discard the process-wide default backend so the next
    :func:`get_default_backend` call creates a fresh, empty one.

    Intended for **test isolation**: the default backend is a
    process-wide singleton, so state (claimed signatures, consumed jtis,
    issuance records) written by one test leaks into the next test's
    default-constructed delegation authorities — a second test minting a payload whose
    canonical bytes were already claimed by an earlier test hits
    ``SignatureReplay`` for no reason of its own. Production code has no
    business calling this mid-deployment (it silently drops shared
    single-use state for every default-constructed component in the
    process); the only sanctioned caller is the test-suite conftest
    fixture.
    """
    global _default_backend
    with _default_backend_lock:
        _default_backend = None
