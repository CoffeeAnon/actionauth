"""End-to-end test for the bridge's MCP HTTP surface.

Exercises ``build_mcp_app`` over Starlette's ``TestClient``: an
unauthenticated request is rejected; an authorised bearer-token
request authenticates and reaches the MCP session handler. The
streamable-HTTP MCP protocol itself has a multi-step handshake we
do NOT replay here (that lives in the mcp SDK's own tests); the
purpose of this file is to verify the bridge's *plumbing* —
authentication, route mount, app construction — works end-to-end.

The HITL-via-elicitation flow on the MCP side is covered by
``test_mcp_hitl_roundtrip.py``, which exercises the building blocks
(translation + consent + delegation authority + RS) end-to-end without depending
on the MCP SDK's elicitation primitive.

Requires `pip install -e '.[mcp]'`.
"""
import typing

import pytest

pytest.importorskip("starlette")
pytest.importorskip("mcp")

from starlette.testclient import TestClient  # noqa: E402
from starlette import types as starlette_types  # noqa: E402

from actionauth.audit import AuditSink  # noqa: E402
from actionauth.auth.hmac import TokenStore  # noqa: E402
from actionauth.core.client import InMemoryTaskStore  # noqa: E402
from actionauth.core.dispatcher import Dispatcher  # noqa: E402
from actionauth.mcp.invoker import InProcessInvoker  # noqa: E402
from actionauth.mcp import server as mcp_server  # noqa: E402
from actionauth.mcp.server import build_mcp_app  # noqa: E402
from actionauth.authority import InProcessAuthority  # noqa: E402

# Ensure command registration before invoker dispatches.
import actionauth.commands  # noqa: F401, E402


SECRET = "mcp-server-test-secret-32bytes-minimum"


@pytest.fixture
def mcp_world(tmp_path):
    audit = AuditSink(str(tmp_path / "audit.db"))
    token_store = TokenStore(str(tmp_path / "tokens.json"))
    token = token_store.issue(["tasks.read"], label="test-client", secret=SECRET)

    store = InMemoryTaskStore()
    store.create(title="A")
    store.create(title="B")
    authority = InProcessAuthority(secret=SECRET)
    dispatcher = Dispatcher(client=store, authority=authority)
    invoker = InProcessInvoker(dispatcher)

    app = build_mcp_app(
        invoker=invoker, audit=audit, token_store=token_store, secret=SECRET,
    )
    return app, token


def test_mcp_mount_rejects_unauthenticated_requests(mcp_world):
    app, _ = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post("/mcp")  # no Authorization header
    assert resp.status_code == 401
    body = resp.json()
    assert "unauthorized" in body["error"]["message"]


def test_mcp_mount_rejects_bogus_bearer_token(mcp_world):
    app, _ = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={"Authorization": "Bearer not-a-real-token"},
        )
    assert resp.status_code == 401


def test_mcp_mount_accepts_authenticated_request_and_reaches_session_manager(mcp_world):
    """A valid bearer token gets past the bridge auth wrapper. The MCP
    SDK's session manager then handles the request (and may reject it
    for protocol-level reasons unrelated to our auth — we only assert
    that the auth gate passed, i.e. status != 401)."""
    app, token = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
                "mcp-session-id": "test-session",
            },
            json={"jsonrpc": "2.0", "method": "initialize", "id": 1,
                  "params": {"protocolVersion": "2024-11-05",
                             "capabilities": {},
                             "clientInfo": {"name": "test", "version": "0"}}},
        )
    # 401 = bridge auth rejected us; anything else means we made it through
    # the auth wrapper into the MCP session manager.
    assert resp.status_code != 401


def test_mcp_mount_has_correct_route(mcp_world):
    """Defensive: the mount is at /mcp, not the root or some other path."""
    app, _ = mcp_world
    routes = app.routes()
    assert len(routes) == 1
    assert "/mcp" in str(routes[0])


# ---------------------------------------------------------------------------
# Mcp-Method / Mcp-Name per-request header validation (work order item 2)
# ---------------------------------------------------------------------------

def _auth_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/json, text/event-stream",
        "Content-Type": "application/json",
    }


def test_header_mcp_method_matching_body_is_accepted(mcp_world):
    """(a) Mcp-Method present and matching the body's method -> not a 400.

    A valid token + a consistent header means we pass both the auth gate and
    the header-validation gate. We assert status != 401 (auth passed) AND
    status != 400 (header gate passed); the MCP session manager may then
    answer with a protocol-level response of its own."""
    app, token = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={**_auth_headers(token), "mcp-method": "tools/list"},
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 7, "params": {}},
        )
    assert resp.status_code != 401, "auth gate must pass"
    assert resp.status_code != 400, "consistent Mcp-Method must not be rejected"


def test_header_mcp_method_contradicting_body_is_rejected(mcp_world):
    """(b) Mcp-Method present but contradicting the body's method -> 400."""
    app, token = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={**_auth_headers(token), "mcp-method": "tools/list"},
            json={"jsonrpc": "2.0", "method": "tools/call", "id": 8,
                  "params": {"name": "task_create"}},
        )
    assert resp.status_code == 400
    assert "contradict" in resp.json()["error"]["message"]


def test_header_mcp_name_contradicting_body_is_rejected(mcp_world):
    """(c) Mcp-Name present but contradicting the body's name -> 400."""
    app, token = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={**_auth_headers(token), "mcp-name": "task_create"},
            json={"jsonrpc": "2.0", "method": "tools/call", "id": 9,
                  "params": {"name": "task_delete"}},
        )
    assert resp.status_code == 400
    assert "contradict" in resp.json()["error"]["message"]


def test_header_both_mcp_method_and_name_matching_is_accepted(mcp_world):
    """(d) Both headers present and both consistent with the body -> not 400."""
    app, token = mcp_world
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers={**_auth_headers(token),
                     "mcp-method": "tools/call", "mcp-name": "task_create"},
            json={"jsonrpc": "2.0", "method": "tools/call", "id": 10,
                  "params": {"name": "task_create"}},
        )
    assert resp.status_code != 401
    assert resp.status_code != 400, "consistent Mcp-Method+Mcp-Name must not be rejected"


def test_header_duplicate_mcp_method_is_rejected(mcp_world):
    """(e) Duplicate Mcp-Method header (two values) -> 400."""
    app, token = mcp_world
    # httpx accepts a list of (name, value) tuples to emit duplicate headers.
    with TestClient(app.starlette_app()) as client:
        resp = client.post(
            "/mcp",
            headers=[
                ("Authorization", f"Bearer {token}"),
                ("Accept", "application/json, text/event-stream"),
                ("Content-Type", "application/json"),
                ("mcp-method", "tools/list"),
                ("mcp-method", "tools/call"),
            ],
            json={"jsonrpc": "2.0", "method": "tools/list", "id": 11, "params": {}},
        )
    assert resp.status_code == 400
    assert "duplicate" in resp.json()["error"]["message"]


# ---------------------------------------------------------------------------
# Dead annotation
# ---------------------------------------------------------------------------

def test_send_json_response_annotations_resolve():
    """``_send_json_response``'s ``send`` parameter must annotate a name the
    module actually defines.

    The annotation is stored as a string (``from __future__ import
    annotations``), so a typo'ed / never-imported name (the historical
    ``ASGISend``) survives import and module load — an import smoke test
    proves nothing. Forcing resolution with ``typing.get_type_hints`` makes
    the bug loud: pre-fix it raises ``NameError: name 'ASGISend' is not
    defined``; post-fix the ``send`` annotation resolves to the imported
    ``starlette.types.Send``. Real function, real resolver, no mock.
    """
    hints = typing.get_type_hints(mcp_server._send_json_response)
    assert "send" in hints
    # ``==``, not ``is``: starlette's ``Send`` is a type alias, and a
    # resolved alias is not ``is``-identical to the alias object itself, but
    # it must equal it. (Pre-fix this call raised NameError before any
    # assertion — the test fails on the bug, not on the comparison.)
    assert hints["send"] == starlette_types.Send

