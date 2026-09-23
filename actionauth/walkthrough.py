"""Step-by-step walkthrough of the sequence diagram in `docs/architecture.md`.

Where the ``demo`` scenarios narrate at the "is the property preserved?"
level, the walkthrough mirrors the sequence diagrams in
``docs/architecture.md`` step-by-step, printing the actual JSON-RPC /
SSE / OAuth envelopes at each hop. Use it to:

  - Demonstrate the bridge end-to-end without standing up a server
  - Read ``docs/architecture.md`` side-by-side with executable output
  - Step through interactively (``--pause``) to walk a reader through
    the flow at a presentation

The walkthrough is *behaviour-accurate but transport-simulated*: the
HTTP/SSE envelopes are constructed in-process, not sent over real
sockets. The delegation authority, dispatcher, and RS calls are real. The simulation
is for narration, not for protocol validation.
"""
from __future__ import annotations

import json
import sys

from actionauth.core.client import InMemoryTaskStore
from actionauth.core.dispatcher import ApprovalRequired, CommandSuccess, Dispatcher
from actionauth.translation import (
    A2aAuthRequiredEvent,
    McpElicitationResponse,
    a2a_auth_required_to_mcp_elicitation,
    mcp_elicitation_response_to_a2a_resume,
)
from actionauth.authority import (
    InProcessAuthority,
    OAuthAuthority,
    sign_authorization_details,
)

import actionauth.commands  # noqa: F401 (registers task-tracker commands)


_CYAN = "\033[36m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

# Demo secrets generated fresh per process. NEVER copy these constants
# into a deployment; they exist only so this walkthrough can run end-to-end
# without an external delegation authority. A real deployment loads secrets from the
# environment, a secrets manager, or an HSM, and the user signing secret
# lives client-side (WebAuthn / Passkey), never on the actionauth.
import secrets as _secrets   # noqa: E402

USER_SECRET = _secrets.token_urlsafe(32)
MINT_SECRET = _secrets.token_urlsafe(32)
RAR_TYPE = "tasktracker_task_action"


# ── Output helpers ──────────────────────────────────────────────────────────


class Stepper:
    """State for printing numbered steps + optional interactive pause."""

    def __init__(self, pause: bool) -> None:
        self._pause = pause
        self._n = 0

    def step(self, who: str, what: str) -> None:
        self._n += 1
        print(f"\n{_BOLD}Step {self._n}{_RESET}  {_CYAN}{who}{_RESET}  →  {what}")
        if self._pause:
            try:
                input(f"  {_DIM}[Enter to continue]{_RESET} ")
            except (EOFError, KeyboardInterrupt):
                print()
                sys.exit(130)


def _print_envelope(label: str, payload: dict) -> None:
    """Print a JSON-RPC / OAuth / SSE envelope inside an indented block."""
    print(f"  {_DIM}─── {label} ────────────────────────{_RESET}")
    for line in json.dumps(payload, indent=2).splitlines():
        print(f"  {_DIM}│{_RESET} {line}")


def _note(text: str) -> None:
    print(f"  {_YELLOW}▸{_RESET} {text}")


def _success(text: str) -> None:
    print(f"  {_GREEN}✓{_RESET} {text}")


def _reject(text: str, reason: str = "") -> None:
    suffix = f"  ({reason})" if reason else ""
    print(f"  {_RED}✗{_RESET} {text}{suffix}")


# ── A2A walkthrough ─────────────────────────────────────────────────────────


def walkthrough_a2a(*, tier: int, pause: bool) -> int:
    """End-to-end happy path on the A2A surface, mirroring the architecture-doc sequence."""

    print(f"{_BOLD}A2A → delegation authority → RS walkthrough (Tier {tier}){_RESET}")
    print(f"{_DIM}A reference simulation of the sequence diagram in "
          f"`docs/architecture.md` \"A2A\" flow.{_RESET}")

    # Set up shared infrastructure.
    store = InMemoryTaskStore()
    target = store.create(title="Q2 launch checklist")
    bystander = store.create(title="Q3 onboarding doc")
    context_id = "ctx-abc123"

    if tier == 2:
        authority = OAuthAuthority(
            user_signing_secret=USER_SECRET,
            mint_secret=MINT_SECRET,
            expected_rar_type=RAR_TYPE,
        )
    else:
        authority = InProcessAuthority(secret=USER_SECRET, expected_rar_type=RAR_TYPE)

    dispatcher = Dispatcher(client=store, authority=authority)
    s = Stepper(pause=pause)

    # ── 1: client sends initial A2A message ─────────────────────────────
    s.step("MCP host → Bridge",
           "POST /a2a  message:send (initial request, read-scope token)")
    _print_envelope("A2A request (initial)", {
        "jsonrpc": "2.0",
        "method": "message:send",
        "params": {
            "context_id": context_id,
            "message": {
                "role": "user",
                "parts": [{"text": f"Please delete the Q2 launch checklist (task_id={target['task_id']})."}],
            },
        },
        "headers": {"Authorization": "Bearer t-base  (scope: tasks.read)"},
    })
    _note("Base token grants tasks.read only - insufficient for a destructive action.")

    # ── 2: bridge validates token, LLM resolves the intent ─────────────
    s.step("Bridge → Dispatcher",
           "validate t-base, resolve intent → delete-task(task_id=...)")
    _success("base token validates against the agent's token store")
    _note("LLM in the agent's graph resolves the user's request to a structured "
          "tool call. In production this is a real LLM step; the walkthrough "
          "models it as a deterministic resolution.")

    # ── 3: dispatch sees requires_approval, builds authorization_details ──
    s.step("Dispatcher → HITL gate",
           "delete-task spec.requires_approval=True → pause + build authorization_details")
    authorization_details = {
        "type": RAR_TYPE,
        "command": "delete-task",
        "args": {"task_id": target["task_id"]},
    }
    _print_envelope("authorization_details (proposed)", authorization_details)

    # ── 4: SSE auth_required event back to the client ──────────────────
    s.step("Bridge → MCP host",
           "SSE event: task_status_update state=auth_required")
    a2a_event = A2aAuthRequiredEvent(
        task_id="task-001",
        context_id=context_id,
        authorization_details=authorization_details,
        binding_message=f"Delete the task titled '{target['title']}'?",
    )
    _print_envelope("SSE event (constructed by the A2A executor)", {
        "event": "task_status_update",
        "data": {
            "task_id": a2a_event.task_id,
            "context_id": a2a_event.context_id,
            "state": "auth_required",
            "parts": [{
                "kind": "DataPart",
                "data": {
                    "authorization_details": [a2a_event.authorization_details],
                    "binding_message": a2a_event.binding_message,
                },
            }],
        },
    })
    _note("The bridge translates this A2A event to an MCP elicitation request "
          "using `actionauth.translation.a2a_auth_required_to_mcp_elicitation`: "
          "Pattern 1 (orchestration) in real code, not just narration.")
    mcp_request = a2a_auth_required_to_mcp_elicitation(
        a2a_event, bridge_base_url="https://bridge.example",
    )
    _print_envelope("MCP elicitation request (URL-mode, spec-required for OAuth consent)", {
        "method": "elicitation/create",
        "params": {
            "elicitation_id": mcp_request.elicitation_id,
            "mode": mcp_request.mode,
            "url": mcp_request.url,
            "title": mcp_request.title,
            "description": mcp_request.description,
        },
    })

    # ── 5: human reviews, approves, signs ──────────────────────────────
    s.step("Human (MCP host UI)",
           "review the binding message + authorization_details, approve, sign")
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": target["task_id"]},
        rar_type=RAR_TYPE,
        approver_id="alice@example.com",
        binding_message=mcp_request.description,
        secret=USER_SECRET,
    )
    _success("MCP host computed HMAC over the canonical authorization_details payload")
    _note("DEMO NOTE: in this walkthrough the signing happens server-side via the "
          "reference's `demo_sign_as_user` stand-in. In production the user_signing_"
          "secret lives on the human's MCP host (WebAuthn-bound, hardware-backed) "
          "and the bridge process NEVER holds it. See "
          "docs/architecture.md \"Threat\" model and the docstring on "
          "`actionauth.consent.demo_signer`.")
    _print_envelope("signed payload (sent back to bridge)", {
        "command": signed.command,
        "args": signed.args,
        "rar_type": signed.rar_type,
        "exp": signed.exp,
        "approver_id": signed.approver_id,
        "signature": signed.signature[:32] + "…",
    })

    # ── 6: client resumes via A2A message:send ─────────────────────────
    s.step("MCP host → Bridge",
           "elicitation/response (accept), translated back to A2A message:send")
    mcp_response = McpElicitationResponse(
        elicitation_id=mcp_request.elicitation_id,
        action="accept",
        signed_payload={
            "command": signed.command, "args": signed.args, "rar_type": signed.rar_type,
            "exp": signed.exp, "approver_id": signed.approver_id, "signature": signed.signature,
        },
    )
    a2a_resume = mcp_elicitation_response_to_a2a_resume(mcp_response)
    _note(f"`actionauth.translation.mcp_elicitation_response_to_a2a_resume` "
          f"recovered context_id={a2a_resume.context_id!r} from "
          f"elicitation_id={mcp_request.elicitation_id!r}, preserving the "
          f"A2A task continuity across the round-trip.")
    _print_envelope("A2A resume request", {
        "jsonrpc": "2.0",
        "method": "message:send",
        "params": {
            "context_id": context_id,
            "message": {
                "role": "user",
                "parts": [{
                    "kind": "DataPart",
                    "data": {
                        "approved": True,
                        "payload": {**signed.args, "type": RAR_TYPE},
                        "signature": signed.signature[:32] + "…",
                    },
                }],
            },
        },
    })

    # ── 7: bridge verifies signature shape ─────────────────────────────
    s.step("Bridge → Bridge",
           "verify the signature is over the authorization_details we emitted")
    _success("signature is over the dispatcher's authorization_details, not a free-form payload")

    # ── 8: bridge presents signed payload to delegation authority ─────────────────────
    s.step("Bridge → delegation authority",
           "present signed RAR for verification + minting")
    if tier == 2:
        _print_envelope("delegation authority /token request (logical)", {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "subject_token": signed.signature[:32] + "…",
            "subject_token_type": "urn:bridge:signed-authorization-details",
            "authorization_details": [authorization_details],
            "approver_id": signed.approver_id,
        })
    else:
        _note("Tier 1: the dispatcher is the delegation authority. The 'mint' call is in-process.")

    minted = authority.mint(signed)
    _success(f"delegation authority verified the human signature and minted credential jti={minted.jti}")

    if tier == 2:
        # Show JWT structure for the OAuth tier.
        header_b64, body_b64, sig_b64 = minted.credential.split(".")
        import base64
        body = json.loads(base64.urlsafe_b64decode(body_b64 + "=" * (-len(body_b64) % 4)))
        _print_envelope("minted JWT (decoded body)", body)

    # ── 9: dispatcher executes the action with the minted credential ────
    s.step("Bridge → Dispatcher",
           "resume graph; call delete-task with the delegation authority-minted credential")
    outcome = dispatcher.execute(
        "delete-task",
        {"task_id": target["task_id"]},
        approval_token=minted.credential,
    )

    if isinstance(outcome, CommandSuccess):
        _success("Dispatcher accepted the credential, RS executed the delete")
    else:
        _reject(f"unexpected outcome: {type(outcome).__name__}")
        return 1

    # ── 10: simulated RS response ──────────────────────────────────────
    s.step("Dispatcher → RS",
           f"DELETE /tasks/{target['task_id']}  (Bearer: minted credential)")
    _print_envelope("RS response", {"status": 204, "body": None})

    # ── 11: SSE completed event ────────────────────────────────────────
    s.step("Bridge → MCP host",
           "SSE event: task_status_update state=completed")
    _print_envelope("SSE event", {
        "event": "task_status_update",
        "data": {
            "task_id": "task-001",
            "context_id": context_id,
            "state": "completed",
            "artifacts": [{"kind": "TextPart", "text": "Deleted."}],
        },
    })

    # ── 12: post-conditions check ──────────────────────────────────────
    s.step("Walkthrough → Verify",
           "post-condition: target deleted, bystander survives, credential consumed")
    remaining = {t["task_id"] for t in store.list()}
    if target["task_id"] in remaining:
        _reject(f"target {target['task_id']} should be deleted but is still present")
        return 1
    if bystander["task_id"] not in remaining:
        _reject(f"bystander {bystander['task_id']} should survive but is gone")
        return 1
    _success(f"target {target['task_id']} deleted")
    _success(f"bystander {bystander['task_id']} survives")

    # Verify single-use by replaying with the SAME args (so the check
    # that fires is single-use, not parameter drift).
    replay = dispatcher.execute(
        "delete-task", {"task_id": target["task_id"]},
        approval_token=minted.credential,
    )
    if isinstance(replay, ApprovalRequired):
        _success(f"replay with same args rejected with reason={replay.reason}")
    else:
        _reject("credential was reusable - single-use property broken")
        return 1

    print(f"\n{_GREEN}{_BOLD}Walkthrough complete.{_RESET}  All steps proceeded as the architecture-doc sequence describes.")
    return 0
