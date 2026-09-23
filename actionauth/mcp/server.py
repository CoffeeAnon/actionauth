"""MCP server: build_mcp_app() returns a mountable Starlette sub-app.

Uses mcp.server.lowlevel.Server with explicit Tool definitions so each
ToolSpec's JSON Schema travels through verbatim — no signature inference.

SDK version: mcp >= 2.0.0 (2026-07-28 stateless protocol).
Import paths confirmed against the installed 2.0.0:
  - mcp.server.lowlevel.Server
  - mcp.server.streamable_http_manager.StreamableHTTPSessionManager
  - mcp.types (Tool, InputRequiredResult, ElicitRequest, etc.)

Handler registration uses the 2.0.0 ``add_request_handler`` API
(the 1.x decorator API ``@server.list_tools()`` / ``@server.call_tool()``
was removed in 2.0.0).
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import logging
from contextvars import ContextVar
from dataclasses import dataclass
from collections.abc import AsyncIterator
from typing import Any

from mcp import types as mcp_types
from mcp.server.context import ServerRequestContext
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from mcp.shared.exceptions import UrlElicitationRequiredError
from starlette.applications import Starlette
from starlette.routing import Mount
from starlette.types import Receive, Send

from actionauth.audit import AuditRow, AuditSink
from actionauth.mcp.invoker import ToolInvoker
from actionauth.mcp.hitl import McpHitlGate, consent_session_id
from actionauth.auth.hmac import CallerIdentity, TokenStore
from actionauth.mcp.auth import AuthError, verify_bearer
from actionauth.mcp.tools import mcp_tool_specs
from actionauth.authority import AuthorityError

logger = logging.getLogger(__name__)


# The MRTR surface (``InputRequiredResult`` / ``input_responses`` /
# ``request_state``) only exists on the 2026-07-28 protocol version: the
# tools/call result union on every earlier version is ``CallToolResult`` only,
# so an ``InputRequiredResult`` returned to a client negotiating
# 2025-03-26 (or 2024-11-05) fails the SDK's per-version result validation
# with ``-32603 invalid result``. Clients on those versions must instead be
# given the legacy URL-mode elicitation (``-32042``).
_MRTR_PROTOCOL_VERSION = "2026-07-28"


def _is_modern_protocol(version: str | None) -> bool:
    """True if the negotiated protocol version carries the MRTR surface."""
    return (version or "") >= _MRTR_PROTOCOL_VERSION


def _pending_consent_result(
    version: str | None, *, url: str, session_id: str, message: str
) -> Any:
    """Result for a HITL-gated call that is not yet approved.

    Modern protocol (>= 2026-07-28): return the MRTR ``InputRequiredResult``
    keyed by the consent session id; the client retries with
    ``input_responses`` + ``request_state`` once the human approves.

    Legacy protocol: raise the URL-mode elicitation error (``-32042``) the
    1.x clients were written against. The consent session is created
    idempotently before this is reached, so both paths resume against the
    same durable session.
    """
    elicit = mcp_types.ElicitRequestURLParams(
        mode="url",
        message=message,
        url=url,
        elicitation_id=session_id,
    )
    if _is_modern_protocol(version):
        elicitation = mcp_types.ElicitRequest(
            method="elicitation/create", params=elicit
        )
        return mcp_types.InputRequiredResult(
            input_requests={"consent": elicitation},
            request_state=session_id,
            result_type="input_required",
        )
    raise UrlElicitationRequiredError([elicit], message=message)


# ContextVar used by the tool-call handler to attribute calls to the right caller.
_CURRENT_CALLER: ContextVar[CallerIdentity | None] = ContextVar("mcp_current_caller", default=None)


class _ToolCallError(Exception):
    """Raised by the tool handler when a tool-level failure occurs
    (execution reported ok=False, MRTR resume rejected, approval
    payload malformed, etc.).

    Per the MCP contract, tool *execution* failures are tool-level
    results (``CallToolResult(is_error=True)``), not JSON-RPC errors.
    The 2.0.0 SDK would otherwise map a plain exception to a bare
    ``-32603 "Internal server error"``, discarding the message. The
    wrapper installed at handler-registration time catches this and
    returns the error result; protocol-level failures (unknown tool,
    malformed request) still raise and surface as JSON-RPC errors.
    """


def _make_call_tool_wrapper(dispatch):
    """Wrap a tools/call dispatch function so ``_ToolCallError`` surfaces
    as ``CallToolResult(is_error=True)`` instead of a bare ``-32603``.
    """

    async def _call_tool_handler(ctx, params):
        try:
            return await dispatch(ctx, params)
        except _ToolCallError as e:
            return mcp_types.CallToolResult(
                content=[mcp_types.TextContent(type="text", text=str(e))],
                is_error=True,
                result_type="complete",
            )
        except AuthorityError as e:
            # A delegation authority failure on the HITL resume path (minting the
            # credential for an approved action) is a tool-level outcome,
            # not a server fault. ``DelegationAuthority.mint`` raises a ``AuthorityError``
            # subclass for every verification failure — ``CredentialExpired``
            # when the approved payload's validity window closed before the
            # retry, ``SignatureMismatch``, ``PayloadDriftAtMint``,
            # ``SignatureReplay`` — and none of them is a ``RuntimeError``,
            # so without this arm the SDK renders a bare -32603 and throws
            # the reason away. The reason is the actionable part: "your
            # approval's credential window closed" tells the agent to
            # re-initiate consent; "Internal server error" tells it nothing.
            # Placed before ``RuntimeError`` and after ``_ToolCallError`` so
            # neither existing arm changes behaviour.
            return mcp_types.CallToolResult(
                content=[
                    mcp_types.TextContent(
                        type="text",
                        text=(
                            f"Approval credential error ({type(e).__name__}): {e}. "
                            "Re-initiate consent for this action and retry."
                        ),
                    )
                ],
                is_error=True,
                result_type="complete",
            )
        except RuntimeError as e:
            # DurableConsentStore.create() surfaces an impossible-state
            # wedge (a freshly-created row already expired — clock
            # rewind or TTL edge) as RuntimeError. That is a
            # tool-level outcome, not a server fault: report it as an
            # error result instead of a bare -32603.
            return mcp_types.CallToolResult(
                content=[
                    mcp_types.TextContent(
                        type="text",
                        text=f"MRTR session state error: {e}",
                    )
                ],
                is_error=True,
                result_type="complete",
            )

    return _call_tool_handler


def _binding_message(command: str, args: dict) -> str:
    """Human-readable summary of the proposed action, rendered on the consent
    page and bound into the signed canonical bytes. Demo-grade: production
    sources this from a per-tool renderer, not string interpolation."""
    arg_text = ", ".join(f"{k}={v}" for k, v in sorted(args.items()))
    return f"Approve action: {command} ({arg_text})" if arg_text else f"Approve action: {command}"


# ---------------------------------------------------------------------------
# Mcp-Method / Mcp-Name header validation (2026-07-28 stateless protocol)
# ---------------------------------------------------------------------------

# The SDK's inbound.py defines these constants; we use the same lowercase
# header names to avoid a hard import of an internal module.
_MCP_METHOD_HEADER = "mcp-method"
_MCP_NAME_HEADER = "mcp-name"


def _validate_mcp_headers(
    scope: dict,
    body: bytes,
) -> tuple[str | None, str | None] | None:
    """Validate Mcp-Method / Mcp-Name headers against the JSON-RPC body.

    Returns:
      - None if no headers are present (nothing to validate).
      - ("method", "name") if headers are present and consistent.
      - Raises ValueError with a human-readable message if headers
        contradict the body, are duplicated, or are inconsistent with
        each other.

    Rules (per the 2026-07-28 spec and the card work order):
      - Both headers present and either contradicts the body → error.
      - Only one header present → validate it matches the body.
      - Duplicate header (two values for the same header) → error.
    """
    raw_headers = scope.get("headers", [])
    # Collect all values per header name (detect duplicates).
    method_values: list[str] = []
    name_values: list[str] = []
    for k, v in raw_headers:
        key = k.decode().lower()
        val = v.decode()
        if key == _MCP_METHOD_HEADER:
            method_values.append(val)
        elif key == _MCP_NAME_HEADER:
            name_values.append(val)

    if not method_values and not name_values:
        return None  # no headers to validate

    # Duplicate detection
    if len(method_values) > 1:
        raise ValueError(
            f"duplicate Mcp-Method header: {method_values}"
        )
    if len(name_values) > 1:
        raise ValueError(
            f"duplicate Mcp-Name header: {name_values}"
        )

    # Parse the JSON-RPC body to extract method and name.
    try:
        body_obj = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise ValueError("body is not valid JSON; cannot validate Mcp-Method/Mcp-Name headers")

    # The body may be a single JSON-RPC object or a batch (list).
    # We validate against the first object for simplicity (batches with
    # mixed methods are out of scope for this reference).
    if isinstance(body_obj, list):
        body_obj = body_obj[0] if body_obj else {}
    body_method = body_obj.get("method", "")
    body_name = body_obj.get("params", {}).get("name", "") if isinstance(body_obj.get("params"), dict) else ""

    header_method = method_values[0] if method_values else None
    header_name = name_values[0] if name_values else None

    # Validate Mcp-Method if present.
    if header_method is not None:
        if body_method and header_method != body_method:
            raise ValueError(
                f"Mcp-Method header '{header_method}' contradicts JSON-RPC body method '{body_method}'"
            )
        if not body_method:
            raise ValueError(
                f"Mcp-Method header '{header_method}' present but body has no method field"
            )

    # Validate Mcp-Name if present (only meaningful for name-bearing methods).
    if header_name is not None:
        if body_name and header_name != body_name:
            raise ValueError(
                f"Mcp-Name header '{header_name}' contradicts JSON-RPC body name '{body_name}'"
            )
        if not body_name and body_method in ("tools/call", "resources/read", "prompts/get"):
            raise ValueError(
                f"Mcp-Name header '{header_name}' present but body has no name field for method '{body_method}'"
            )

    return (header_method, header_name)


async def _read_body(scope: dict, receive: Receive) -> bytes:
    """Read the full request body from the ASGI receive channel."""
    body_chunks: list[bytes] = []
    while True:
        message = await receive()
        if message["type"] == "http.request":
            body_chunks.append(message.get("body", b""))
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break
    return b"".join(body_chunks)


async def _send_json_response(scope: dict, send: Send, status_code: int, payload: dict) -> None:
    """Send a raw ASGI JSON response."""
    body = json.dumps(payload).encode()
    await send({
        "type": "http.response.start",
        "status": status_code,
        "headers": [
            [b"content-type", b"application/json"],
            [b"content-length", str(len(body)).encode()],
        ],
    })
    await send({
        "type": "http.response.body",
        "body": body,
    })


# ---------------------------------------------------------------------------
# MRTR (Multi-Request-Then-Respond) helpers
# ---------------------------------------------------------------------------

def _canonical_action_hash(command: str, args: dict) -> str:
    """SHA-256 of canonical JSON of (command, args). Used to bind the
    continuation token to the exact action the human approved."""
    canonical = json.dumps(
        {"command": command, "args": args},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode()
    return hashlib.sha256(canonical).hexdigest()


@dataclass
class McpApp:
    """Adapter holding the lowlevel Server + the Starlette mount."""
    starlette: Starlette
    server: Server

    def starlette_app(self) -> Starlette:
        return self.starlette

    def routes(self) -> list:
        return list(self.starlette.routes)


def build_mcp_app(
    *,
    invoker: ToolInvoker,
    audit: AuditSink,
    token_store: TokenStore,
    secret: str,
    consent_store=None,
    authority=None,
    rar_type: str = "tasktracker_task_action",
    bridge_base_url: str = "https://bridge.invalid",
) -> McpApp:
    """Construct a Starlette app exposing /mcp with bearer auth.

    The session manager is started/stopped via Starlette's lifespan mechanism.
    Wrap TestClient usage in a `with` block to trigger the lifespan:
        with TestClient(app.starlette_app()) as client: ...

    HITL: when ``consent_store`` and ``authority`` are supplied, a HITL-gated
    ``tools/call`` uses the MRTR (Multi-Request-Then-Respond) flow:
    the first call returns ``InputRequiredResult`` with a continuation
    token; the client retries with ``inputResponses`` + ``requestState``
    after the human approves at the consent surface. A legacy URL-mode
    elicitation fallback is retained for 1.x clients.

    Omit ``consent_store``/``authority`` and the surface stays read-only.
    """
    server = Server("task-tracker-mcp", version="0.1.0")

    gate = (
        McpHitlGate(
            consent_store=consent_store,
            bridge_base_url=bridge_base_url,
            rar_type=rar_type,
            authority=authority,
        )
        if consent_store is not None and authority is not None
        else None
    )

    specs_by_name = {s.name: s for s in mcp_tool_specs(include_hitl=gate is not None)}

    # ------------------------------------------------------------------
    # tools/list handler (2.0.0 add_request_handler API)
    # ------------------------------------------------------------------
    async def _list_tools_handler(ctx: Any, params: Any) -> Any:
        tools = [
            mcp_types.Tool(
                name=spec.name,
                description=spec.description,
                inputSchema=spec.parameters,
            )
            for spec in mcp_tool_specs(include_hitl=gate is not None)
        ]
        return mcp_types.ListToolsResult(tools=tools)

    server.add_request_handler("tools/list", mcp_types.PaginatedRequestParams, _list_tools_handler)

    # ------------------------------------------------------------------
    # tools/call handler (2.0.0 add_request_handler API) with MRTR
    # ------------------------------------------------------------------
    async def _dispatch_tool_call(ctx: ServerRequestContext, params: mcp_types.CallToolRequestParams) -> Any:
        name = params.name
        arguments = params.arguments or {}

        spec = specs_by_name.get(name)
        if spec is None:
            raise ValueError(f"Unknown tool: {name}")

        caller = _CURRENT_CALLER.get()
        actor = f"mcp:{caller.display_name}" if caller else "mcp:unknown"
        thread_id = f"mcp:{caller.caller_id}" if caller else "mcp:anon"
        caller_id = caller.caller_id if caller else "mcp:anon"

        # --- MRTR resume path ---
        # If the request carries input_responses + request_state, this is
        # a retry after an InputRequiredResult. Verify the token, caller,
        # and canonical action hash, then mint and re-dispatch.
        if params.input_responses is not None and params.request_state is not None:
            token = params.request_state
            # Look up the continuation token in the durable consent store.
            # The token IS the consent session id (deterministic, derived
            # from caller+command+args at first-call time).
            req = gate._store.get(token) if gate else None
            if req is None or req.signed_payload is None:
                raise _ToolCallError(
                    "MRTR resume failed: consent token not found or not yet approved. "
                    "Complete the consent flow and retry."
                )
            # Verify caller matches the one bound into the token.
            if req.approver_id != caller_id:
                raise _ToolCallError(
                    "MRTR resume failed: caller mismatch. The consent token was "
                    "issued to a different caller."
                )
            # Verify canonical action hash matches.
            # NOTE: the consent session records the CLI command name
            # (spec.cli_name, e.g. "delete-task") from the dispatcher's
            # ApprovalRequired outcome, NOT the MCP tool name ("delete_task").
            # Both sides must hash over the same canonical command — the one
            # that actually executes — so compare against spec.cli_name here.
            if spec.cli_name is None:
                raise _ToolCallError(
                    "MRTR resume failed: tool has no executable CLI command."
                )
            expected_hash = _canonical_action_hash(req.command, dict(req.args))
            actual_hash = _canonical_action_hash(spec.cli_name, arguments)
            if expected_hash != actual_hash:
                raise _ToolCallError(
                    "MRTR resume failed: action hash mismatch. The retried "
                    "action does not match the approved action."
                )
            # All checks passed — mint (or reuse the cached credential) and
            # re-dispatch. Gate.try_resume goes through the durable
            # minted-credential cache: a repeat resume of an already-minted
            # session returns the SAME credential instead of re-presenting
            # the signed payload (which the delegation authority's SignatureReplay guard
            # would reject with an uncaught -32603).
            token_credential = gate.try_resume(
                command=req.command, args=dict(req.args), caller_id=caller_id
            )
            if token_credential is None:
                raise _ToolCallError(
                    "MRTR resume failed: approval not usable. "
                    "Complete the consent flow and retry."
                )
            result = invoker.invoke(
                spec, arguments, approval_token=token_credential, caller=caller
            )
        else:
            # --- Initial call path ---
            result = invoker.invoke(spec, arguments, caller=caller)

            # HITL: if approval is required, enter MRTR flow.
            if result.approval_required and gate is not None:
                payload = result.approval_payload or {}
                cmd, cmd_args = payload.get("command"), payload.get("args", {})
                if not cmd or not isinstance(cmd_args, dict):
                    raise _ToolCallError(
                        "Approval payload malformed: missing command or args."
                    )
                binding = _binding_message(cmd, cmd_args)
                sid = consent_session_id(caller_id=caller_id, command=cmd, args=cmd_args)

                # Create (idempotently) the pending consent session.
                gate._store.create(
                    command=cmd,
                    args=cmd_args,
                    rar_type=rar_type,
                    approver_id=caller_id,
                    binding_message=binding,
                    session_id=sid,
                )

                # Check if already approved (idempotent retry without MRTR).
                existing = gate._store.get(sid)
                if existing is not None and existing.signed_payload is not None:
                    # Already approved — mint (or reuse cached credential)
                    # and re-dispatch. Gate.try_resume goes through the
                    # durable minted-credential cache so a repeat call does
                    # not re-present the signed payload (SignatureReplay).
                    cred = gate.try_resume(
                        command=cmd, args=cmd_args, caller_id=caller_id
                    )
                    if cred is None:
                        raise _ToolCallError(
                            "Approval not usable. Complete the consent "
                            "flow and retry."
                        )
                    result = invoker.invoke(
                        spec, arguments, approval_token=cred, caller=caller
                    )
                else:
                    # Not yet approved — emit the version-appropriate result:
                    # MRTR InputRequiredResult (>= 2026-07-28) or the legacy
                    # -32042 URL-elicitation error (earlier versions). The
                    # helper either returns the MRTR result (which MUST be
                    # returned here — falling through would hit the common
                    # result handling below with result.ok still False) or
                    # raises the legacy elicitation error, which propagates.
                    return _pending_consent_result(
                        ctx.protocol_version,
                        url=f"{bridge_base_url.rstrip('/')}/consent/{sid}",
                        session_id=sid,
                        message=binding,
                    )

        # --- Common result handling ---
        full_content = result.content or ""
        snippet = full_content[:500]

        audit.write(AuditRow(
            thread_id=thread_id,
            tenant_id="mcp",
            kind="tool_call",
            tool_name=name,
            tool_args=str(arguments)[:500],
            result_snippet=snippet,
            actor=actor,
        ))

        if not result.ok:
            raise _ToolCallError(full_content)

        return mcp_types.CallToolResult(
            content=[mcp_types.TextContent(type="text", text=full_content)],
            result_type="complete",
        )

    server.add_request_handler(
        "tools/call", mcp_types.CallToolRequestParams,
        _make_call_tool_wrapper(_dispatch_tool_call),
    )

    session_manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)

    async def _handle_mcp(scope: dict, receive: Receive, send: Send) -> None:
        """ASGI callable: bearer-auth + Mcp-Method/Mcp-Name header wrapper
        around the MCP session manager."""
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        auth_header = headers.get("authorization", "")
        try:
            caller = verify_bearer(auth_header, token_store, secret)
        except AuthError as e:
            logger.warning("mcp_auth_reject reason=%s remote=%s", e.reason, scope.get("client"))
            await _send_json_response(scope, send, 401, {
                "jsonrpc": "2.0",
                "error": {"code": -32001, "message": f"unauthorized: {e.reason}"},
                "id": None,
            })
            return

        # Read and buffer the body so we can validate headers, then
        # replay it for the session manager.
        body = await _read_body(scope, receive)

        # Validate Mcp-Method / Mcp-Name headers against the body.
        try:
            _validate_mcp_headers(scope, body)
        except ValueError as e:
            await _send_json_response(scope, send, 400, {
                "jsonrpc": "2.0",
                "error": {"code": -32600, "message": f"header validation failed: {e}"},
                "id": None,
            })
            return

        # Replay the body for the session manager.
        body_consumed = False

        async def _replay_receive() -> dict:
            nonlocal body_consumed
            if not body_consumed:
                body_consumed = True
                return {
                    "type": "http.request",
                    "body": body,
                    "more_body": False,
                }
            # Subsequent calls: wait for disconnect (the session manager
            # may call receive again for the disconnect signal).
            return await receive()

        token = _CURRENT_CALLER.set(caller)
        try:
            await session_manager.handle_request(scope, _replay_receive, send)
        finally:
            _CURRENT_CALLER.reset(token)

    @contextlib.asynccontextmanager
    async def _lifespan(app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    starlette = Starlette(
        routes=[Mount("/mcp", app=_handle_mcp)],
        lifespan=_lifespan,
    )
    return McpApp(starlette=starlette, server=server)
