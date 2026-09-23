# actionauth.mcp

MCP HTTP server for the task-tracker reference agent. It exposes a subset of tools from `actionauth.tools` over HTTP using the Anthropic MCP Python SDK, with HMAC bearer token authentication. The endpoints are read-only unless configured with human-in-the-loop (HITL) approval, in which case sensitive tools become callable through a URL-based consent flow.

## Components

| Module       | Purpose                                                                                                       |
| ------------ | ------------------------------------------------------------------------------------------------------------- |
| `server.py`  | `build_mcp_app(*, invoker, audit, token_store, secret, consent_store=None, authority=None, ...)` returns a Starlette ASGI app mounted at `/mcp`. Passing `consent_store` and `authority` enables the HITL gate. |
| `invoker.py` | `InProcessInvoker` adapts MCP tool calls to the internal `actionauth.core.dispatcher`.                             |
| `auth.py`    | `verify_bearer(...)` validates `Authorization: Bearer <token>` headers against `actionauth.auth.hmac.TokenStore`. |
| `hitl.py`    | `McpHitlGate` emits URL elicitations for gated tools and resumes calls after approval.                        |
| `tools.py`   | Defines `MCP_V1_ALLOWLIST` (read tools) and `MCP_HITL_ALLOWLIST` (gated tools), plus a defense-in-depth filter.|

## Exposed tools and permissions

`actionauth/mcp/tools.py` controls tool visibility using two allowlists:
- `MCP_V1_ALLOWLIST` lists read-only tools that are always exposed. A defense-in-depth filter automatically excludes any tool marked `requires_approval=True` or `in_process=True`, even if erroneously added to this list.
- `MCP_HITL_ALLOWLIST` lists sensitive tools (such as `delete_task`). These are registered only when `build_mcp_app` receives both a `consent_store` and a `authority`. Without these dependencies, the server runs in read-only mode.

When HITL gating is active, calling a gated tool returns a URL elicitation (`URL_ELICITATION_REQUIRED`) pointing to the consent UI. Once the user approves the action, retrying the call completes execution. See `docs/architecture.md` for sequence details and `tests/e2e/test_mcp_elicitation_emission.py` for an end-to-end test.

## Tests

- `tests/protocol/test_mcp_read_filter.py`: Verifies tool allowlists and safety filters.
- `tests/protocol/test_mcp_server.py`: Verifies bearer authentication handling over HTTP.
- `tests/unit/test_mcp_hitl_gate.py`: Verifies `McpHitlGate` elicitation and resume behavior.
- `tests/e2e/test_mcp_elicitation_emission.py`: Verifies the full approval flow: emit, approve, resume, and execute.

## Optional dependencies

Install optional MCP dependencies with `pip install -e '.[mcp]'` (installs `mcp`, `starlette`, `uvicorn`, and `python-multipart`). The core repository (CLI demos, delegation authority, and dispatcher) runs on standard library Python without these packages.

## Protocol boundary

Plain tool calls go through `Dispatcher`. `InProcessInvoker` (`actionauth/mcp/invoker.py`) adapts incoming MCP requests onto `Dispatcher.execute`, where scope enforcement occurs.

The human-approval path does not go through `Dispatcher`. `McpHitlGate` (`actionauth/mcp/hitl.py`) wires in `StateBackend` and the consent stores (`ConsentStore`, `DurableConsentStore`), and calls the delegation authority directly (`self._authority.mint(signed)`) to mint warrants. `actionauth/mcp/server.py` also depends directly on `AuditSink` (`actionauth/audit.py`) and on `AuthorityError`.

Shared HMAC token utilities live separately in `actionauth.auth.hmac`.

Wrapping `Dispatcher` alone reproduces plain tool dispatch, but not the approval workflow. A new protocol adapter, such as gRPC or native A2A, must implement its own equivalent of the approval gate to emit elicitations, wire in consent storage, and call the delegation authority to mint credentials.
