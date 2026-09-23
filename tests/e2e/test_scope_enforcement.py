"""Dispatcher-level scope enforcement (see `SECURITY.md`).

These tests exercise the scope-vs-HITL orthogonality:

  - A caller without ``tasks.write`` cannot execute non-HITL writes
    (``create_task``, ``update_task``) just because they aren't gated
    by an approval flow.
  - A caller without ``tasks.write`` cannot reach the HITL gate at
    all for destructive actions — scope check runs *before* HITL.
  - A caller with the right scopes proceeds as before.
  - A no-caller dispatch (trusted in-process: CLI / walkthrough)
    bypasses scope enforcement by design.
"""
from actionauth.auth.hmac import CallerIdentity
from actionauth.core.client import InMemoryTaskStore
from actionauth.core.dispatcher import (
    ApprovalRequired,
    CommandSuccess,
    Dispatcher,
    Unauthorized,
)
from actionauth.authority import InProcessAuthority


SECRET = "scope-enforcement-test-32bytes-pad"


def _authority() -> InProcessAuthority:
    return InProcessAuthority(secret=SECRET, expected_rar_type="tasktracker_task_action")


def _read_only_caller() -> CallerIdentity:
    return CallerIdentity(
        caller_id="abcdef01", display_name="reader-bot",
        scopes=frozenset({"tasks.read"}),
    )


def _write_caller() -> CallerIdentity:
    return CallerIdentity(
        caller_id="01234567", display_name="writer-bot",
        scopes=frozenset({"tasks.read", "tasks.write"}),
    )


def _seeded() -> InMemoryTaskStore:
    store = InMemoryTaskStore()
    store.create(title="alpha")
    store.create(title="beta")
    return store


def test_read_scope_allows_list_tasks():
    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    outcome = dispatcher.execute("list-tasks", {}, caller=_read_only_caller())
    assert isinstance(outcome, CommandSuccess)


def test_read_only_caller_refused_at_non_hitl_write():
    """The whole point of scope enforcement: a tasks.read bearer
    cannot execute create_task just because it isn't HITL-gated."""
    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    outcome = dispatcher.execute(
        "create-task", {"title": "should not be created"},
        caller=_read_only_caller(),
    )
    assert isinstance(outcome, Unauthorized)
    assert "tasks.write" in outcome.required_scopes
    assert "tasks.write" not in outcome.caller_scopes
    assert outcome.caller_id == "abcdef01"


def test_read_only_caller_refused_at_hitl_write_BEFORE_approval_check():
    """Scope check runs before HITL routing. A read-only caller
    presenting no approval_token for delete_task gets ``Unauthorized``,
    not ``ApprovalRequired`` — the distinction matters for audit
    attribution and to prevent leaking "this action could be approved"
    information to under-privileged callers.
    """
    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    outcome = dispatcher.execute(
        "delete-task", {"task_id": "t-1"},
        caller=_read_only_caller(),
    )
    assert isinstance(outcome, Unauthorized)
    assert not isinstance(outcome, ApprovalRequired)


def test_write_scope_allows_non_hitl_write():
    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    outcome = dispatcher.execute(
        "create-task", {"title": "new task"},
        caller=_write_caller(),
    )
    assert isinstance(outcome, CommandSuccess)


def test_write_scope_reaches_hitl_gate_for_destructive():
    """A write-scoped caller passes the scope check but still needs
    a credential for HITL-gated tools — they hit ApprovalRequired,
    not Unauthorized."""
    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    outcome = dispatcher.execute(
        "delete-task", {"task_id": "t-1"},
        caller=_write_caller(),
    )
    assert isinstance(outcome, ApprovalRequired)
    assert not isinstance(outcome, Unauthorized)


def test_invoker_returns_unauthorized_toolresult_for_scope_failure():
    """Surface-level: through ``InProcessInvoker.invoke``, a scope
    failure becomes a ToolResult with ``unauthorized=True`` and an
    actionable content message. The MCP server / A2A surface relays
    this to the LLM without ever calling the tool.
    """
    from actionauth.mcp.invoker import InProcessInvoker
    from actionauth.tools import SPECS_BY_NAME

    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    invoker = InProcessInvoker(dispatcher)
    result = invoker.invoke(
        SPECS_BY_NAME["create_task"],
        {"title": "should not be created"},
        caller=_read_only_caller(),
    )
    assert result.ok is False
    assert result.unauthorized is True
    assert "tasks.write" in result.content


def test_no_caller_bypasses_scope_enforcement():
    """CLI / walkthrough / test-harness in-process dispatches pass
    no caller. The dispatcher treats this as a trusted context and
    skips scope enforcement. Externally-reachable surfaces (MCP, A2A)
    MUST always pass a caller; this is enforced by the surface code,
    not the dispatcher.
    """
    dispatcher = Dispatcher(client=_seeded(), authority=_authority())
    outcome = dispatcher.execute("create-task", {"title": "from cli"})
    assert isinstance(outcome, CommandSuccess)
