"""Command dispatcher with HITL gate.

Pure logic: no printing, no exit codes. Used by both the agent's in-process
invoker and any CLI wrapper that wants to call commands directly.

Two enforcement primitives live here, and they are orthogonal:

  1. **Scope enforcement.** Before any execution path, the dispatcher
     checks the caller's bearer-token scopes against the tool's
     ``required_scopes``. A ``tasks.read`` bearer attempting
     ``create_task`` is refused at this point with an ``Unauthorized``
     outcome, *before* HITL routing. The motivating concern: a caller
     whose token does not carry write scope must not be able to
     execute non-HITL writes just because they aren't gated by an
     approval flow. See ``SECURITY.md`` for the discussion.

  2. **HITL gate.** When a command's class declares ``hitl=True``,
     dispatch refuses to execute without a valid credential.
     Validation can happen in one of two places:

       - **delegation authority-backed (Tier 1 in-process):** dispatcher calls
         ``DelegationAuthority.consume(credential, command, args)``. The delegation authority
         holds the consumed-jti state.

       - **RS-backed (Tier 2 with separated RS):** dispatcher forwards
         ``(command, args, credential)`` to ``ResourceServer.execute``,
         which does its own JWT verify + binding check + single-use
         enforcement against the RS's own state, then executes. This
         is the deployment shape the "three independent enforcement
         layers" claim requires.

A ``Dispatcher`` is constructed with exactly one of ``authority=`` or
``resource_server=``; passing neither is a programming error.

The ``caller`` parameter on ``execute`` is the bearer-attributed
identity from the surface (MCP, A2A). When ``caller is None`` the
dispatcher is being invoked from a trusted in-process context (CLI,
walkthrough, tests with no surface) and scope enforcement is bypassed
— this is intentional and documented; an externally-reachable
surface must always pass a ``caller``.
"""
from dataclasses import dataclass
from typing import Any

from actionauth.auth.hmac import CallerIdentity
from actionauth.core.client import ApiError, BridgeClient
from actionauth.core.registry import REGISTRY
from actionauth.rs import JwtResourceServer, RsError, RsRejected, RsSuccess
from actionauth.tools import SPECS_BY_CLI_NAME
from actionauth.authority import AuthorityError, DelegationAuthority


# ── Outcome types: the structured return from Dispatcher.execute() ──────────

@dataclass(frozen=True)
class CommandSuccess:
    items: list[dict]
    meta: dict


@dataclass(frozen=True)
class CommandError:
    status: int | str
    message: str
    context: dict | None


@dataclass(frozen=True)
class ApprovalRequired:
    """Returned when a HITL-gated command was attempted without a valid credential.

    ``reason`` is populated with the delegation authority exception's class name when a
    delegation authority-backed dispatcher refused a presented credential (for example,
    ``"CredentialDrift"``, ``"CredentialReplay"``, ``"CredentialExpired"``,
    ``"SignatureMismatch"``). Callers should treat ``reason`` as an audit-
    attribution hint, not as part of the security contract (the contract
    is "the command did not execute"). ``reason`` is ``None`` when no
    credential was presented at all.
    """
    command: str
    args: dict
    reason: str | None = None


@dataclass(frozen=True)
class Unauthorized:
    """Returned when the caller's bearer scopes do not include the tool's
    ``required_scopes``. Distinct from ``ApprovalRequired``: scope failure
    means "this caller is not allowed to attempt this tool at all";
    approval failure means "this destructive attempt needs a human signed
    consent it does not have." A reader looking at audit rows must be able
    to tell the two apart.
    """
    command: str
    args: dict
    required_scopes: tuple[str, ...]
    caller_scopes: tuple[str, ...]
    caller_id: str | None = None


CommandOutcome = CommandSuccess | CommandError | ApprovalRequired | Unauthorized


_RESERVED_META_KEYS = {"count", "status", "command"}


class Dispatcher:
    """Stateful dispatcher: holds either a delegation authority or a separated Resource
    Server across calls. Exactly one of ``authority`` / ``resource_server``
    must be provided.

    Constructor parameters:
      client: resource-server client used by the delegation authority-backed path
              (defaults to ``InMemoryTaskStore``). Ignored when a
              separated ``resource_server`` is provided - the RS holds
              its own client.
      authority:  ``DelegationAuthority`` implementation. Co-located mint + consume +
              execute in one trust domain.
      resource_server: ``JwtResourceServer`` for the separated shape.
              When provided, the dispatcher forwards
              ``(command, args, credential)`` to the RS, which validates
              the JWT independently against its own state.
    """

    def __init__(
        self,
        client: Any | None = None,
        authority: DelegationAuthority | None = None,
        resource_server: JwtResourceServer | None = None,
    ) -> None:
        if (authority is None) == (resource_server is None):
            raise ValueError(
                "Dispatcher requires exactly one of `authority` or `resource_server`"
            )
        self._client = client if client is not None else BridgeClient()
        self._authority = authority
        self._rs = resource_server

    def execute(
        self,
        command_name: str,
        kwargs: dict,
        approval_token: str | None = None,
        *,
        caller: CallerIdentity | None = None,
    ) -> CommandOutcome:
        """Run a command and return a structured outcome.

        ``caller`` is the bearer-attributed identity. When provided, scope
        enforcement runs against the tool's ``required_scopes`` *before*
        HITL routing. When ``None``, scope enforcement is bypassed and the
        dispatcher assumes a trusted in-process context (CLI, walkthrough,
        test harness). Externally-reachable surfaces (MCP, A2A) MUST pass
        a non-None ``caller``.
        """
        cmd_cls = REGISTRY.get(command_name)
        if cmd_cls is None:
            return CommandError(
                status="unknown",
                message=f"Unknown command: {command_name}",
                context=None,
            )

        collision = _RESERVED_META_KEYS & kwargs.keys()
        if collision:
            raise ValueError(
                f"Command kwargs collide with reserved meta keys {sorted(collision)}; "
                f"rename in your tool spec"
            )

        # Scope enforcement runs before HITL routing so a caller
        # without write scope cannot execute non-HITL writes.
        spec = SPECS_BY_CLI_NAME.get(command_name)
        if caller is not None and spec is not None and spec.required_scopes:
            missing = [s for s in spec.required_scopes if s not in caller.scopes]
            if missing:
                return Unauthorized(
                    command=command_name,
                    args=dict(kwargs),
                    required_scopes=tuple(spec.required_scopes),
                    caller_scopes=tuple(sorted(caller.scopes)),
                    caller_id=caller.caller_id,
                )

        if cmd_cls.hitl:
            if not approval_token:
                return ApprovalRequired(command=command_name, args=dict(kwargs))

            if self._rs is not None:
                return self._execute_via_rs(command_name, kwargs, approval_token)

            return self._execute_via_authority(command_name, kwargs, approval_token, cmd_cls)

        # Non-HITL path: dispatcher executes locally.
        return self._execute_locally(command_name, kwargs, cmd_cls)

    # ── HITL execution paths ────────────────────────────────────────────

    def _execute_via_authority(
        self,
        command_name: str,
        kwargs: dict,
        approval_token: str,
        cmd_cls,
    ) -> CommandOutcome:
        try:
            self._authority.consume(approval_token, command_name, kwargs)
        except AuthorityError as exc:
            return ApprovalRequired(
                command=command_name,
                args=dict(kwargs),
                reason=type(exc).__name__,
            )
        return self._execute_locally(command_name, kwargs, cmd_cls)

    def _execute_via_rs(
        self,
        command_name: str,
        kwargs: dict,
        approval_token: str,
    ) -> CommandOutcome:
        outcome = self._rs.execute(command_name, kwargs, approval_token)
        if isinstance(outcome, RsSuccess):
            return CommandSuccess(items=outcome.items, meta=outcome.meta)
        if isinstance(outcome, RsError):
            return CommandError(
                status=outcome.status, message=outcome.message, context=outcome.context,
            )
        if isinstance(outcome, RsRejected):
            return ApprovalRequired(
                command=command_name,
                args=dict(kwargs),
                reason=outcome.reason,
            )
        # Defensive: unknown RS outcome shape.
        return CommandError(status="rs_unknown_outcome", message=str(outcome), context=None)

    # ── Non-HITL execution ──────────────────────────────────────────────

    def _execute_locally(
        self,
        command_name: str,
        kwargs: dict,
        cmd_cls,
    ) -> CommandOutcome:
        try:
            items = cmd_cls().execute(client=self._client, **kwargs)
        except ApiError as e:
            return CommandError(status=e.status_code, message=e.body, context=dict(kwargs))
        except ValueError as e:
            return CommandError(status=400, message=str(e), context=dict(kwargs))
        meta = {**kwargs, "count": len(items), "status": "ok"}
        return CommandSuccess(items=items, meta=meta)
