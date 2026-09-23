"""Tool invoker — abstracts 'how we call a tool' from 'which tool we're calling'.

`InProcessInvoker` is the production invoker: it calls `Dispatcher.execute()`
directly, no subprocess. The agent and the CLI share the same dispatcher
core; the CLI is just an argparse wrapper around the same execute() that
the agent calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from actionauth.auth.hmac import CallerIdentity
from actionauth.tools import ToolSpec
from actionauth.core.dispatcher import (
    ApprovalRequired,
    CommandError,
    Dispatcher,
    Unauthorized,
)
from actionauth.core.output import error_human, to_human


@dataclass(frozen=True)
class ToolResult:
    """Outcome of invoking one tool."""
    ok: bool
    content: str
    approval_required: bool = False
    approval_payload: dict | None = None   # {"command": str, "args": dict[str,str]}
    unauthorized: bool = False             # bearer scopes don't cover this tool


class ToolInvoker(Protocol):
    def invoke(
        self,
        spec: ToolSpec,
        args: dict,
        approval_token: str | None = None,
        *,
        caller: CallerIdentity | None = None,
    ) -> ToolResult: ...


class InProcessInvoker:
    """The production invoker: calls `Dispatcher.execute()` directly.

    No subprocess, no argv, no stdout parsing. The Dispatcher returns a
    structured outcome (CommandSuccess | CommandError | ApprovalRequired
    | Unauthorized) which we adapt to a ToolResult, formatting items /
    errors as the same human-readable text the CLI emits.
    """

    def __init__(self, dispatcher: Dispatcher) -> None:
        """Construct with an explicitly-configured Dispatcher. The dispatcher
        itself must have been built with a delegation authority or a ResourceServer; the
        invoker does not (and cannot) supply trust substrate defaults."""
        self._dispatcher = dispatcher

    def invoke(
        self,
        spec: ToolSpec,
        args: dict,
        approval_token: str | None = None,
        *,
        caller: CallerIdentity | None = None,
    ) -> ToolResult:
        if spec.in_process:
            raise ValueError(f"{spec.name} is an in-process tool; use a node dispatcher")
        if spec.cli_name is None:
            raise ValueError(f"{spec.name} has no cli_name")

        outcome = self._dispatcher.execute(
            command_name=spec.cli_name,
            kwargs=args,
            approval_token=approval_token,
            caller=caller,
        )

        if isinstance(outcome, Unauthorized):
            missing = sorted(set(outcome.required_scopes) - set(outcome.caller_scopes))
            content = (
                f"unauthorized: tool {spec.name!r} requires scope(s) {missing}; "
                f"caller has {list(outcome.caller_scopes)}"
            )
            return ToolResult(ok=False, content=content, unauthorized=True)

        if isinstance(outcome, ApprovalRequired):
            return ToolResult(
                ok=False,
                content="",
                approval_required=True,
                approval_payload={"command": outcome.command, "args": outcome.args},
            )

        if isinstance(outcome, CommandError):
            content = error_human(spec.cli_name, outcome.status, outcome.message, context=outcome.context)
            return ToolResult(ok=False, content=content)

        # CommandSuccess — format as the same lean human-text the CLI emits
        content = to_human(command=spec.cli_name, items=outcome.items, meta=outcome.meta)
        return ToolResult(ok=True, content=content)
