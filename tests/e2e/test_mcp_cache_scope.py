"""Cache-scope test: no per-caller state leaks into served tool/resource lists.

Requirement:
"make two requests from different callers; verify no tool/resource list
from caller A is served to caller B."

The MCP surface serves a static, read-only toolset that is identical for
every authenticated caller.  The ``_MintedCredentialCache`` is keyed by
consent-session id (which embeds the caller_id), so it is inherently
per-caller — a credential minted for caller A's session is never returned
to caller B.

This test asserts both properties at the wire level (real ASGI, no mock):

  1. ``tools/list`` from caller A and caller B return identical tool sets
     (no caller-specific pollution of the list).
  2. A consent session minted for caller A yields a different session id
     than the same action proposed by caller B, and resuming caller A's
     token as caller B is rejected (the cache is keyed per-caller).
"""
from __future__ import annotations

import json
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
from actionauth.authority.durable_state import DurableReplayState  # noqa: E402

import actionauth.commands  # noqa: F401, E402

PROTOCOL_VERSION = "2026-07-28"
SECRET = "cache-scope-test-secret-32bytes-xx"
RAR_TYPE = "tasktracker_task_action"
BRIDGE_BASE = "https://bridge.example"


def _make_world(tmp_path, shared_backend: DurableReplayState | None = None):
    """Build a full bridge world. When ``shared_backend`` is passed, both
    the authority and the gate's minted-credential cache share it — modelling
    two replicas behind a common StateBackend."""
    db = str(tmp_path)
    audit = AuditSink(f"{db}/audit.db")
    token_store = TokenStore(f"{db}/tokens.json")
    task_store = InMemoryTaskStore()
    if shared_backend is None:
        shared_backend = DurableReplayState(f"{db}/state.sqlite")
    authority = InProcessAuthority(secret=SECRET, durable_state=shared_backend)
    dispatcher = Dispatcher(client=task_store, authority=authority)
    invoker = InProcessInvoker(dispatcher)
    consent_store = DurableConsentStore(f"{db}/consent.sqlite", ttl_seconds=300.0)
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
        "backend": shared_backend,
    }


def _headers(token: str, method: str, name: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
        "mcp-protocol-version": PROTOCOL_VERSION,
        "mcp-method": method,
        "mcp-name": name,
    }


_META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientCapabilities": {},
}


def _post(client, token: str, method: str, name: str, params: dict) -> dict:
    params = dict(params)
    params.setdefault("_meta", dict(_META))
    body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
    r = client.post("/mcp", json=body, headers=_headers(token, method, name))
    assert r.status_code == 200, (r.status_code, r.text)
    if "text/event-stream" in r.headers.get("content-type", ""):
        data = [ln[5:].strip() for ln in r.text.splitlines() if ln.startswith("data:")]
        assert data, r.text
        return json.loads(data[-1])
    return json.loads(r.text)


def _result(body: dict) -> dict:
    assert "error" not in body, f"JSON-RPC error: {body['error']}"
    return body["result"]


# ── 5a. tools/list is caller-independent (no per-caller pollution) ─────────


def test_tools_list_identical_for_two_callers(tmp_path):
    """Two different callers each call tools/list over real HTTP. The tool
    sets must be identical — the surface is a static read-only allowlist
    and no caller-specific state (cache, session, credential) may leak
    into the list served to the other caller."""
    w = _make_world(tmp_path)
    alice = w["token_store"].issue(["tasks.read"], label="alice", secret=SECRET)
    bob = w["token_store"].issue(["tasks.read"], label="bob", secret=SECRET)

    with TestClient(w["app"].starlette_app()) as client:
        # Caller A (alice) lists tools.
        body_a = _post(client, alice, "tools/list", "list_tasks", {})
        res_a = _result(body_a)
        tools_a = {t["name"] for t in res_a["tools"]}

        # Caller B (bob) lists tools — a fresh request, no shared in-proc state.
        body_b = _post(client, bob, "tools/list", "list_tasks", {})
        res_b = _result(body_b)
        tools_b = {t["name"] for t in res_b["tools"]}

    # Both callers see exactly the same tool set. No tool from A's request
    # is "cached" and served to B, nor vice-versa.
    assert tools_a == tools_b, (
        f"tool list leaked caller-specific state: A={tools_a} B={tools_b}"
    )
    # Sanity: the expected read-only + HITL toolset.
    assert tools_a == {"list_tasks", "get_task", "delete_task"}, tools_a


# ── 5b. consent-session cache is keyed per-caller ──────────────────────────


def test_consent_session_id_differs_per_caller(tmp_path):
    """The same destructive action proposed by two different callers yields
    two different consent-session ids (the id embeds caller_id). A token
    minted for caller A's session must NOT be usable by caller B."""
    w = _make_world(tmp_path)
    alice = w["token_store"].issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)
    bob = w["token_store"].issue(["tasks.read", "tasks.write"], label="bob", secret=SECRET)

    victim = w["task_store"].create(title="scope-test-victim")
    tid = victim["task_id"]

    with TestClient(w["app"].starlette_app()) as client, TestClient(w["consent_app"]) as consent:
        # Alice initiates delete_task → gets her own session id.
        res_a = _result(_post(
            client, alice, "tools/call", "delete_task",
            {"name": "delete_task", "arguments": {"task_id": tid}},
        ))
        assert res_a["resultType"] == "input_required"
        sid_a = res_a["requestState"]

        # Bob initiates the SAME action → gets a DIFFERENT session id
        # (the id is a hash of caller+command+args).
        res_b = _result(_post(
            client, bob, "tools/call", "delete_task",
            {"name": "delete_task", "arguments": {"task_id": tid}},
        ))
        assert res_b["resultType"] == "input_required"
        sid_b = res_b["requestState"]

        # Approve Alice's session, then try to resume it as Bob → rejected.
        r = consent.post(f"/consent/{sid_a}/submit", data={"decision": "approve"})
        assert r.status_code == 200, r.text

        # Bob tries to use Alice's token: caller mismatch.
        out = _result(_post(
            client, bob, "tools/call", "delete_task",
            {
                "name": "delete_task",
                "arguments": {"task_id": tid},
                "inputResponses": {"consent": {"action": "accept"}},
                "requestState": sid_a,
            },
        ))
        assert out.get("isError") is True, out
        assert "caller mismatch" in out["content"][0]["text"], out

    # The session ids must differ — the cache key embeds the caller.
    assert sid_a != sid_b, (
        f"consent session id does not distinguish callers: A={sid_a} B={sid_b}"
    )
    # The task must still exist (Bob could not execute Alice's approval).
    assert any(t["task_id"] == tid for t in w["task_store"].list())
