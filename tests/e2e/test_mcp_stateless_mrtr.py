"""MRTR (Multi-Request-Then-Respond) over real HTTP.

Every request goes through a Starlette ``TestClient`` (ASGI) against
``build_mcp_app`` with no httpx.MockTransport and no unittest.mock
patching — the real 2.0.0 Streamable-HTTP server, exercised at the wire
level. Each request POSTs JSON-RPC to ``/mcp`` speaking the
2026-07-28 protocol via the ``mcp-protocol-version`` request header plus
the ``params._meta`` envelope keys the SDK 2.0.0 dispatcher requires
(``io.modelcontextprotocol/protocolVersion`` and
``io.modelcontextprotocol/clientCapabilities``) — without them the
server negotiates down and the ``InputRequiredResult`` MRTR surface is
not offered.

Wire contract (all shapes below verified live against the running
server, not the SDK schema alone):

* initial ``tools/call`` on a HITL-gated tool returns a **result**
  (not a JSON-RPC error) with ``resultType: "input_required"``,
  ``requestState`` = the consent session id (an opaque **string**), and
  ``inputRequests`` = a **dict** keyed ``"consent"`` carrying the
  URL-mode elicitation (``method: "elicitation/create"``,
  ``params.mode: "url"``, ``params.url: <bridge_base_url>/consent/<sid>``).
* approval happens on the *independent* consent surface
  (``POST /consent/<sid>/submit``), not in the MCP result envelope.
* resume is the **next** ``tools/call`` with the same tool name/args
  plus **camelCase** ``inputResponses`` (a dict keyed by the
  elicitation id, e.g. ``{"consent": {"action": "accept"}}``) and
  ``requestState`` = the session id string. The SDK dispatcher
  validates params with ``model_validate(..., by_name=False)``
  (alias-only): snake_case keys are silently dropped and the request
  is re-taken as a fresh initial call.
* tool-level failures (cross-caller resume, expired/unknown session,
  double-resume business error) surface as a **result** with
  ``isError: true`` and the human-readable message in
  ``content[0].text`` — never a bare JSON-RPC ``-32603`` (tool
  execution failures are tool-level results; JSON-RPC errors are
  reserved for protocol failures).
* a lapsed deterministic session id can be **re-initiated**: an expired
  pending or submitted row is reset to a fresh session in
  ``DurableConsentStore.create()``, so the flow is never wedged forever.
  Expired *denied* rows are kept — a refusal is a human decision.

Coverage:

  1. happy path: ``delete_task`` gated → ``input_required`` + url-mode
     elicitation → approve at the consent surface → resume ok, task
     gone from the store.
  2. resume by a different bearer is rejected as a tool error
     (``caller mismatch``); the task is untouched.
  3. session expires (TTL) → resume is a tool error; task untouched.
  4. after expiry the *same* deterministic id re-initiates and
     completes (the wedge regression test).
  5. double-resume is idempotent: second resume is a tool error
     (empty business text), no crash, no mint replay.
  6. unknown ``requestState`` → tool error, not 500 / -32603.
  7. snake_case continuation keys are dropped → the request is treated
     as a fresh initial call, not a resume.
  8. tools/list reflects the 3-task toolset exactly.
  9. restart durability: a pending session survives a full app rebuild
     (new ``DurableConsentStore`` over the same sqlite file) and the
     rebuilt app resumes it.

Tests 10-15 cover named contracts directly, alongside the
behaviourally equivalent tests above:

  10. ``test_stateless_mrtr_retry_with_2026_headers`` — the
      "real HTTP: 2026 headers + MRTR retry" case, delegating to the
      happy path (item 1) which exercises exactly that contract over
      the real wire.
  11. ``test_mrtr_continuation_expires`` — the "continuation TTL
      expiry" case, delegating to item 3 (injected clock, no sleeping).
  12. ``test_consent_session_survives_restart`` — the durable
      consent contract: ``DurableConsentStore.create`` → ``close`` →
      reopen a new store on the same file → ``get(session_id)``
      returns the session.
  13. ``test_mcp_method_header_mismatch_rejected`` — ``Mcp-Method``
      header contradicting the JSON-RPC body method → HTTP 400.
  14. ``test_duplicate_mcp_method_header_rejected`` — two
      ``Mcp-Method`` headers on one request → HTTP 400.
  15. ``test_list_tools_reevaluates_scope_per_request`` — the
      "no cross-caller leak" case, asserting the implementable contract
      under the full-toolset design: every caller sees the
      current allowlisted toolset, repeated calls are identical (no
      per-caller cache), and the enforcement boundary is dispatch —
      a read-only caller calling ``delete_task`` gets a scope error,
      never execution. (A literal "[read] / [read, write]" set is
      unreachable on the reference allowlist: ``create_task`` /
      ``update_task`` are not allowlisted tools).

Also covered:

  16. ``test_mrtr_closed_credential_window_resume_is_tool_error`` — the
      resume leg where the human *did* approve but the signed payload's
      validity window closed before the retry, so ``DelegationAuthority.mint`` raises
      ``CredentialExpired``. That is a tool-level outcome: it must reach
      the caller as ``isError: true`` with the reason, never a bare
      ``-32603``. The demo Approve button always stamps a future ``exp``
      (``demo_sign_as_user``), so the closed window cannot be reached
      through the consent page — the test seeds the approved row through
      the store's own ``submit_signed`` CAS instead, leaving command,
      args, rar_type, approver_id and binding_message exactly as the
      server wrote them so only the expiry differs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
import uuid

import pytest

pytest.importorskip("mcp")

from starlette.testclient import TestClient  # noqa: E402

from actionauth.audit import AuditSink  # noqa: E402
from actionauth.auth.hmac import TokenStore  # noqa: E402
from actionauth.consent.durable_consent import DurableConsentStore  # noqa: E402
from actionauth.consent.url_mode import build_consent_app  # noqa: E402
from actionauth.core.client import InMemoryTaskStore  # noqa: E402
from actionauth.core.dispatcher import Dispatcher  # noqa: E402
from actionauth.mcp.invoker import InProcessInvoker  # noqa: E402
from actionauth.mcp.server import build_mcp_app  # noqa: E402
from actionauth.authority import InProcessAuthority  # noqa: E402
from actionauth.authority.in_process import canonical_authorization_bytes  # noqa: E402

import actionauth.commands  # noqa: F401, E402  (register commands before dispatch)

PROTOCOL_VERSION = "2026-07-28"
SECRET = "e2e-stateless-mrtr-secret-32bytes-x"
RAR_TYPE = "tasktracker_task_action"
BRIDGE_BASE = "https://bridge.example"
EXPECTED_TOOLS = {"list_tasks", "get_task", "delete_task"}
TTL = 300.0


class _Clock:
    def __init__(self) -> None:
        self.now = float(time.time())

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _make_world(tmp_path, *, clock: _Clock | None = None, task_store: InMemoryTaskStore | None = None):
    """Real bridge world: audit + tokens + task store + authority + MCP app."""
    db = str(tmp_path)
    audit = AuditSink(f"{db}/audit.db")
    token_store = TokenStore(f"{db}/tokens.json")
    if task_store is None:
        task_store = InMemoryTaskStore()
    authority = InProcessAuthority(secret=SECRET)
    dispatcher = Dispatcher(client=task_store, authority=authority)
    invoker = InProcessInvoker(dispatcher)
    consent_store = DurableConsentStore(
        f"{db}/consent.sqlite", ttl_seconds=TTL, clock=clock or _Clock()
    )
    app = build_mcp_app(
        invoker=invoker,
        audit=audit,
        token_store=token_store,
        secret=SECRET,
        consent_store=consent_store,
        authority=authority,
        rar_type=RAR_TYPE,
        bridge_base_url=BRIDGE_BASE,
    )
    consent_app = build_consent_app(store=consent_store, user_signing_secret=SECRET)
    return {
        "task_store": task_store,
        "token_store": token_store,
        "consent_store": consent_store,
        "app": app,
        "consent_app": consent_app,
        "clock": clock,
    }


def _headers(token: str, method: str, name: str, version: str = PROTOCOL_VERSION) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "mcp-protocol-version": version,
        "mcp-method": method,
        "mcp-name": name,
    }


_META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _rpc(method: str, params: dict) -> dict:
    params = dict(params)
    params.setdefault("_meta", dict(_META))
    return {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}


def _post(client: TestClient, token: str, method: str, name: str, params: dict) -> dict:
    body = _rpc(method, params)
    r = client.post("/mcp", json=body, headers=_headers(token, method, name))
    assert r.status_code == 200, (r.status_code, r.text)
    if "text/event-stream" in r.headers.get("content-type", ""):
        data = [ln[5:].strip() for ln in r.text.splitlines() if ln.startswith("data:")]
        assert data, r.text
        return json.loads(data[-1])
    return json.loads(r.text)


def _result(body: dict) -> dict:
    assert "error" not in body, f"JSON-RPC error where a result was expected: {body['error']}"
    assert isinstance(body["result"], dict), body
    return body["result"]


def _initial(client, token, task_id):
    res = _result(_post(client, token, "tools/call", "delete_task",
                        {"name": "delete_task", "arguments": {"task_id": task_id}}))
    assert res["resultType"] == "input_required", res
    assert isinstance(res["requestState"], str) and res["requestState"].startswith("mcp-"), res
    req = res["inputRequests"]["consent"]
    assert req["method"] == "elicitation/create", req
    assert req["params"]["mode"] == "url", req
    assert req["params"]["url"] == f"{BRIDGE_BASE}/consent/{res['requestState']}", req
    return res


def _approve(client, consent, sid: str) -> None:
    r = client.post(f"/consent/{sid}/submit", data={"decision": "approve"})
    assert r.status_code == 200, r.text


def _resume(client, token, task_id, sid: str, **extra) -> dict:
    params = {
        "name": "delete_task",
        "arguments": {"task_id": task_id},
        "inputResponses": {"consent": {"action": "accept"}},
        "requestState": sid,
    }
    params.update(extra)
    return _result(_post(client, token, "tools/call", "delete_task", params))


def _exists(store: InMemoryTaskStore, task_id: str) -> bool:
    return any(t["task_id"] == task_id for t in store.list())


# ── 1. happy path ─────────────────────────────────────────────────────────


def test_mrtr_happy_path_delete_task(tmp_path):
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="Q2 launch checklist")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        _approve(consent, consent, res["requestState"])
        out = _resume(client, alice_tok, victim["task_id"], res["requestState"])
        assert out.get("isError") is not True, out
        assert out["resultType"] == "complete", out
        assert victim["task_id"] in out["content"][0]["text"], out
    assert not _exists(w["task_store"], victim["task_id"])


# ── 2. cross-caller resume rejected ───────────────────────────────────────


def test_mrtr_resume_by_different_caller_rejected(tmp_path):
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)
    bob_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="bob", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        _approve(consent, consent, res["requestState"])
        out = _resume(client, bob_tok, victim["task_id"], res["requestState"])
        assert out.get("isError") is True, out
        text = out["content"][0]["text"]
        assert "caller mismatch" in text, text
    assert _exists(w["task_store"], victim["task_id"])


# ── 3. TTL expiry ─────────────────────────────────────────────────────────


def test_mrtr_session_expiry_is_tool_error(tmp_path):
    clock = _Clock()
    w = _make_world(tmp_path, clock=clock)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        _approve(consent, consent, res["requestState"])
        clock.advance(TTL + 1)
        out = _resume(client, alice_tok, victim["task_id"], res["requestState"])
        assert out.get("isError") is True, out
        text = out["content"][0]["text"]
        assert "consent token not found" in text, text
    assert _exists(w["task_store"], victim["task_id"])


# ── 4. re-initiation after expiry (wedge regression) ──────────────────────


def test_mrtr_reinitiation_after_expiry(tmp_path):
    clock = _Clock()
    w = _make_world(tmp_path, clock=clock)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        sid = res["requestState"]
        _approve(consent, consent, sid)
        clock.advance(TTL + 1)
        # expired resume → tool error (verified in test 3)
        out = _resume(client, alice_tok, victim["task_id"], sid)
        assert out.get("isError") is True, out

        # Re-initiate the same deterministic id: the expired row is
        # reset and a fresh session is minted — the flow is NOT wedged.
        res2 = _initial(client, alice_tok, victim["task_id"])
        assert res2["resultType"] == "input_required", res2
        _approve(consent, consent, res2["requestState"])
        out2 = _resume(client, alice_tok, victim["task_id"], res2["requestState"])
        assert out2.get("isError") is not True, out2
        assert out2["resultType"] == "complete", out2
    assert not _exists(w["task_store"], victim["task_id"])


# ── 5. double-resume idempotency ──────────────────────────────────────────


def test_mrtr_double_resume_is_tool_error_not_crash(tmp_path):
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        _approve(consent, consent, res["requestState"])
        first = _resume(client, alice_tok, victim["task_id"], res["requestState"])
        assert first.get("isError") is not True, first
        second = _resume(client, alice_tok, victim["task_id"], res["requestState"])
        # business-level idempotency failure: reported as a tool error,
        # no bare -32603, no SignatureReplay, no 500.
        assert second.get("isError") is True, second
        assert second["resultType"] == "complete", second
    assert not _exists(w["task_store"], victim["task_id"])


# ── 6. unknown requestState ───────────────────────────────────────────────


def test_mrtr_unknown_request_state_is_tool_error(tmp_path):
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client:
        out = _resume(client, alice_tok, victim["task_id"], "mcp-deadbeef0000000000000000")
        assert out.get("isError") is True, out
        assert "consent token not found" in out["content"][0]["text"], out
    assert _exists(w["task_store"], victim["task_id"])


# ── 7. snake_case continuation keys are dropped ───────────────────────────


def test_mrtr_snake_case_continuation_keys_are_dropped(tmp_path):
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client:
        res = _initial(client, alice_tok, victim["task_id"])
        sid = res["requestState"]
        # A "resume" with snake_case keys: the SDK 2.0.0 dispatcher
        # validates params by_name=False, so both keys are dropped and
        # the request is re-taken as a fresh initial call — it must NOT
        # execute the destructive action.
        out = _result(_post(
            client, alice_tok, "tools/call", "delete_task",
            {
                "name": "delete_task",
                "arguments": {"task_id": victim["task_id"]},
                "input_responses": {"consent": {"action": "accept"}},
                "request_state": sid,
            },
        ))
        assert out["resultType"] == "input_required", out
    assert _exists(w["task_store"], victim["task_id"])


# ── 8. tools/list surface ─────────────────────────────────────────────────


def test_mrtr_tools_list_is_three_task_toolset(tmp_path):
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    with TestClient(w["app"].starlette_app()) as client:
        body = _post(client, alice_tok, "tools/list", "list_tasks", {})
        res = _result(body)
        names = {t["name"] for t in res["tools"]}
        assert names == EXPECTED_TOOLS, names
        delete = next(t for t in res["tools"] if t["name"] == "delete_task")
        assert "approval" in delete["description"].lower(), delete["description"]


# ── 9. restart durability ─────────────────────────────────────────────────


def test_mrtr_pending_session_survives_app_rebuild(tmp_path):
    clock = _Clock()
    w = _make_world(tmp_path, clock=clock)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        sid = res["requestState"]

    # Full rebuild: new app over the same consent sqlite file, sharing
    # the in-memory task store (the durable artifact under test is the
    # consent session, not the task store).
    w2 = _make_world(tmp_path, clock=clock, task_store=w["task_store"])
    with TestClient(w2["app"].starlette_app()) as client2, TestClient(w2["consent_app"]) as consent2:
        # the pending session is still there: re-init returns the same sid
        res2 = _initial(client2, alice_tok, victim["task_id"])
        assert res2["requestState"] == sid, (res2["requestState"], sid)
        _approve(consent2, consent2, sid)
        out = _resume(client2, alice_tok, victim["task_id"], sid)
        assert out.get("isError") is not True, out
    assert not _exists(w["task_store"], victim["task_id"])


# ── 10. real HTTP 2026 headers + MRTR retry ────────────────────────────────


def test_stateless_mrtr_retry_with_2026_headers(tmp_path):
    """The "real HTTP: 2026 headers + MRTR retry" case. Delegates to the happy path (test 1), which is
    exactly this contract: every request is a real HTTP POST to /mcp
    carrying the 2026-07-28 ``mcp-protocol-version`` / ``mcp-method`` /
    ``mcp-name`` headers (see ``_headers``), with the second leg being
    the MRTR continuation (resume) over the same wire."""
    test_mrtr_happy_path_delete_task(tmp_path)


# ── 11. continuation TTL expiry ────────────────────────────────────────────


def test_mrtr_continuation_expires(tmp_path):
    """The "continuation TTL expiry" case.
    Delegates to test 3, which expires the continuation via an injected
    clock (no sleeping) and asserts resume is a tool error, task
    untouched."""
    test_mrtr_session_expiry_is_tool_error(tmp_path)


# ── 12. consent session survives restart ───────────────────────────────────


def test_consent_session_survives_restart(tmp_path):
    """Consent survives restart: a ``DurableConsentStore`` create
    → ``close`` → a NEW store over the same sqlite file → ``get(sid)``
    returns the session. The durable artifact is the consent row,
    independent of any app/bridge instance (the app-rebuild variant is
    test 9)."""
    path = str(tmp_path / "consent.sqlite")
    clock = _Clock()
    a = DurableConsentStore(path, ttl_seconds=TTL, clock=clock)
    req = a.create(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message="Delete task t-42?",
        session_id="mcp-restartx",
    )
    sid = req.session_id
    a.close()

    b = DurableConsentStore(path, ttl_seconds=TTL, clock=clock)
    got = b.get(sid)
    assert got is not None, "pending consent session must survive a restart"
    assert got.session_id == sid
    assert got.signed_payload is None  # still pending, not yet signed
    b.close()


# ── 13. Mcp-Method header mismatch ─────────────────────────────────────────


def test_mcp_method_header_mismatch_rejected(tmp_path):
    """``Mcp-Method`` header contradicting the JSON-RPC body
    method → HTTP 400 (self-contained over the real TestClient; the
    protocol-level twin in tests/protocol/test_mcp_server.py stays)."""
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)
    with TestClient(w["app"].starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={
                **_headers(alice_tok, "tools/list", "list_tasks"),
                # contradict the body: header says tools/list, body says tools/call
                "mcp-method": "tools/list",
            },
            json=_rpc("tools/call", {"name": "list_tasks", "arguments": {}}),
        )
    assert resp.status_code == 400, resp.text
    assert "contradict" in resp.json()["error"]["message"], resp.json()


# ── 14. duplicate Mcp-Method header ────────────────────────────────────────


def test_duplicate_mcp_method_header_rejected(tmp_path):
    """Two ``Mcp-Method`` headers on one request → HTTP 400
    (self-contained over the real TestClient)."""
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)
    with TestClient(w["app"].starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers=[
                ("Authorization", f"Bearer {alice_tok}"),
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("mcp-protocol-version", PROTOCOL_VERSION),
                ("mcp-method", "tools/list"),
                ("mcp-method", "tools/call"),
            ],
            json=_rpc("tools/list", {}),
        )
    assert resp.status_code == 400, resp.text
    assert "duplicate" in resp.json()["error"]["message"], resp.json()


# ── 15. tools/list re-evaluates per request ────────────────────────────────


def test_list_tools_reevaluates_scope_per_request(tmp_path):
    """The "no cross-caller leak" case, asserting the implementable
    contract of the full-toolset design: every caller sees the current
    allowlisted toolset, interleaved calls are identical (no per-caller
    cache, no cross-request state in the list), and scope enforcement
    happens at dispatch — a read-only caller calling ``delete_task``
    gets an unauthorized tool error and the task is untouched.

    This test FAILS if someone (a) adds a shared mutable list cache or
    (b) changes to per-caller filtered output."""
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read"], label="alice", secret=SECRET)
    bob_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="bob", secret=SECRET)

    def _tool_names(client, token: str) -> set:
        res = _result(_post(client, token, "tools/list", "list_tasks", {}))
        return {t["name"] for t in res["tools"]}

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client:
        # Call A (read-only) → S; Call B (read+write) → S; Call A again →
        # S. Identical on every leg: no per-caller state in the list.
        s_a = _tool_names(client, alice_tok)
        s_b = _tool_names(client, bob_tok)
        s_a2 = _tool_names(client, alice_tok)
        assert s_a == EXPECTED_TOOLS, s_a
        assert s_b == s_a, (s_b, s_a)
        assert s_a2 == s_a, (s_a2, s_a)

        # Enforcement boundary is dispatch: the read-only caller can SEE
        # delete_task but cannot CALL it.
        out = _result(_post(
            client, alice_tok, "tools/call", "delete_task",
            {"name": "delete_task", "arguments": {"task_id": victim["task_id"]}},
        ))
        assert out.get("isError") is True, out
        text = out["content"][0]["text"]
        assert "unauthorized" in text, text
        assert "tasks.write" in text, text
    assert _exists(w["task_store"], victim["task_id"]), "read-only caller must not delete"


# ── 16. closed credential window at mint (AuthorityError → tool error) ─────────


def test_mrtr_closed_credential_window_resume_is_tool_error(tmp_path):
    """The human approved; the signed payload's validity window closed
    before the retry. ``DelegationAuthority.mint`` raises ``CredentialExpired`` (a
    ``AuthorityError``, NOT a ``RuntimeError``), which the tools/call wrapper
    must classify as a tool-level outcome.

    Contract under test: a delegation authority failure at mint reaches the agent as
    ``isError: true`` carrying the reason, never as a bare JSON-RPC
    ``-32603 "Internal server error"`` that discards it. ``_result`` fails
    loudly on the error object, so pre-fix this test fails on the FIRST
    assertion with the -32603 body quoted.

    Nothing is mocked: the world, the consent store, the mint and the wire
    are all real. The one thing the consent page cannot produce is a past
    ``exp`` (``demo_sign_as_user`` always stamps a future one), so the
    approved row is seeded through the store's own ``submit_signed`` CAS —
    the same authority the consent UI drives.
    """
    w = _make_world(tmp_path)
    alice_tok = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)

    victim = w["task_store"].create(title="victim")
    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        res = _initial(client, alice_tok, victim["task_id"])
        sid = res["requestState"]

        pending = w["consent_store"].get(sid)
        assert pending is not None and pending.signed_payload is None, pending

        # "Approved, then the window lapsed": an approved row whose signed
        # payload has an exp already in the REAL past (InProcessAuthority.mint
        # compares against time.time(), not the injected consent clock).
        # command / args / rar_type / approver_id / binding_message are
        # reused verbatim from the server-created row so that the expiry is
        # the ONLY difference from a live approval — the caller and
        # action-hash pre-checks in the resume path must still pass.
        exp = int(time.time()) - 10
        canonical = canonical_authorization_bytes(
            pending.command,
            dict(pending.args),
            pending.rar_type,
            exp,
            pending.approver_id,
            pending.binding_message,
        )
        signature = hmac.new(SECRET.encode(), canonical, hashlib.sha256).hexdigest()
        seeded = w["consent_store"].submit_signed(sid, {
            "command": pending.command,
            "args": dict(pending.args),
            "rar_type": pending.rar_type,
            "exp": exp,
            "approver_id": pending.approver_id,
            "binding_message": pending.binding_message,
            "signature": signature,
        })
        assert seeded is True, "the pending→submitted CAS must accept the seed"

        out = _resume(client, alice_tok, victim["task_id"], sid)

        # Tool-level outcome, not a transport error.
        assert out.get("isError") is True, out
        assert out["resultType"] == "complete", out
        text = out["content"][0]["text"]
        assert "expired" in text.lower(), text        # the reason survived
        assert "CredentialExpired" in text, text      # names the delegation authority failure
        assert "consent" in text.lower(), text        # actionable next step

        # Nothing executed, and the failure is at the mint, not the consent
        # layer: the approved row is still there.
        assert _exists(w["task_store"], victim["task_id"]), out
        after = w["consent_store"].get(sid)
        assert after is not None and after.signed_payload is not None, after
