"""Functional-test CLI for ActionAuth.

Stdlib argparse only, no typer/click dependency. Each demo subcommand
walks through one end-to-end scenario, prints the steps with a stable
``[OK]`` / ``[REJECTED]`` / ``[ERROR]`` envelope, and exits with a
non-zero code on any unexpected outcome, so the CLI doubles as a
smoke-test runner.

Invocations::

    python -m actionauth.cli demo tier1            # Pattern-2 happy path on Tier 1
    python -m actionauth.cli demo tier2            # Pattern-2 happy path on Tier 2
    python -m actionauth.cli demo drift [--tier 1|2]    # parameter-drift rejected
    python -m actionauth.cli demo replay [--tier 1|2]   # credential-replay rejected
    python -m actionauth.cli demo key-isolation    # cross-delegation authority key independence
    python -m actionauth.cli demo translation      # Pattern-1 A2A↔MCP round-trip
    python -m actionauth.cli demo all              # run every scenario, print summary

    python -m actionauth.cli walkthrough --tier 2          # narrate the architecture-doc sequence
    python -m actionauth.cli walkthrough --tier 2 --pause  # step-by-step

Exit codes::

    0   every step proceeded as expected
    1   a step produced an unexpected outcome (test failure)
    2   CLI usage error
"""
from __future__ import annotations

import argparse
import sys
from collections.abc import Callable

from actionauth.core.client import InMemoryTaskStore
from actionauth.core.dispatcher import (
    ApprovalRequired,
    CommandSuccess,
    Dispatcher,
)
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

# Importing this package registers all task-tracker commands.
import actionauth.commands  # noqa: F401


# ── Output helpers ──────────────────────────────────────────────────────────


_GREEN = "\033[32m"
_RED = "\033[31m"
_DIM = "\033[2m"
_BOLD = "\033[1m"
_RESET = "\033[0m"


def _step(label: str, detail: str = "") -> None:
    """Print a numbered narration line. Stable format for grep-friendliness."""
    print(f"  {_DIM}…{_RESET} {label}{(' ' + detail) if detail else ''}")


def _ok(label: str) -> None:
    print(f"  {_GREEN}[OK]{_RESET} {label}")


def _rejected(label: str, reason: str = "") -> None:
    suffix = f"  ({reason})" if reason else ""
    print(f"  {_GREEN}[REJECTED]{_RESET} {label}{suffix}")


def _fail(label: str) -> None:
    print(f"  {_RED}[FAIL]{_RESET} {label}")


def _header(name: str) -> None:
    print(f"\n{_BOLD}── {name} ─{_RESET}{'─' * (60 - len(name))}")


def _outcome_summary(name: str, ok: bool) -> None:
    flag = f"{_GREEN}PASS{_RESET}" if ok else f"{_RED}FAIL{_RESET}"
    print(f"  {flag}  {name}")


# ── Scenario primitives ─────────────────────────────────────────────────────


# Demo secrets generated fresh per process. NEVER copy these constants
# into a deployment; they exist only so the CLI scenarios run end-to-end
# without an external delegation authority. A real deployment loads secrets from the
# environment, a secrets manager, or an HSM, and the user signing secret
# lives client-side (WebAuthn / Passkey), never on the actionauth.
import secrets as _secrets

USER_SECRET = _secrets.token_urlsafe(32)
MINT_SECRET = _secrets.token_urlsafe(32)
RAR_TYPE = "tasktracker_task_action"


def _seed_two_tasks() -> tuple[InMemoryTaskStore, str, str]:
    """Common fixture: a fresh store with two tasks, returns (store, A_id, B_id)."""
    store = InMemoryTaskStore()
    a = store.create(title="Task A (approved for deletion)")
    b = store.create(title="Task B (must survive)")
    return store, a["task_id"], b["task_id"]


def _build_authority(tier: int):
    """Construct the requested delegation authority implementation."""
    if tier == 1:
        return InProcessAuthority(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    if tier == 2:
        return OAuthAuthority(
            user_signing_secret=USER_SECRET,
            mint_secret=MINT_SECRET,
            expected_rar_type=RAR_TYPE,
        )
    raise ValueError(f"unknown tier: {tier}")


def _sign_and_mint(authority, command: str, args: dict, approver_id: str = "alice"):
    """Step-narrated sign-then-mint."""
    _step(f"Human reviews proposed action and signs RAR payload (approver={approver_id})")
    binding_message = f"{command} {args}"
    signed = sign_authorization_details(
        command=command, args=args, rar_type=RAR_TYPE,
        approver_id=approver_id, binding_message=binding_message,
        secret=USER_SECRET,
    )
    _step("Bridge presents signed payload to delegation authority for minting")
    minted = authority.mint(signed)
    _ok(f"delegation authority minted credential jti={minted.jti}")
    return minted


# ── Scenarios ───────────────────────────────────────────────────────────────


def scenario_full_flow(tier: int) -> bool:
    """Happy path: human approves a delete, bridge mints, dispatcher executes."""
    _header(f"Tier {tier}: full flow (approved delete)")
    store, task_a, task_b = _seed_two_tasks()
    authority = _build_authority(tier)
    dispatcher = Dispatcher(client=store, authority=authority)

    minted = _sign_and_mint(authority, "delete-task", {"task_id": task_a})
    _step(f"Dispatcher receives delete-task(task_id={task_a}) with the minted credential")
    outcome = dispatcher.execute("delete-task", {"task_id": task_a}, approval_token=minted.credential)

    if not isinstance(outcome, CommandSuccess):
        _fail(f"expected CommandSuccess, got {type(outcome).__name__}")
        return False
    _ok("Dispatcher executed the action and returned CommandSuccess")

    remaining = {t["task_id"] for t in store.list()}
    if task_a in remaining:
        _fail(f"task {task_a} was supposed to be deleted but is still in the store")
        return False
    if task_b not in remaining:
        _fail(f"task {task_b} was not approved for deletion but is missing")
        return False
    _ok("Approved task is deleted; bystander task survives")
    return True


def scenario_parameter_drift(tier: int) -> bool:
    """LLM substitutes a different task_id after the human's approval. Dispatcher refuses."""
    _header(f"Tier {tier}: parameter drift (LLM substitutes a different task_id)")
    store, task_a, task_b = _seed_two_tasks()
    authority = _build_authority(tier)
    dispatcher = Dispatcher(client=store, authority=authority)

    minted = _sign_and_mint(authority, "delete-task", {"task_id": task_a})
    _step(f"After approval, LLM (adversary) substitutes task_id={task_b}")
    outcome = dispatcher.execute("delete-task", {"task_id": task_b}, approval_token=minted.credential)

    if not isinstance(outcome, ApprovalRequired):
        _fail(f"expected ApprovalRequired, got {type(outcome).__name__}")
        return False
    _rejected("Dispatcher refused the drifted action", reason=outcome.reason or "")

    remaining = {t["task_id"] for t in store.list()}
    if task_a not in remaining or task_b not in remaining:
        _fail("a task was deleted despite the dispatcher refusing")
        return False
    _ok("Both tasks survive - drift attempt did not reach the executor")
    return True


def scenario_replay(tier: int) -> bool:
    """Same credential used twice. Second use is rejected."""
    _header(f"Tier {tier}: replay (credential reused)")
    store, task_a, _ = _seed_two_tasks()
    authority = _build_authority(tier)
    dispatcher = Dispatcher(client=store, authority=authority)

    minted = _sign_and_mint(authority, "delete-task", {"task_id": task_a})
    _step("First execution")
    first = dispatcher.execute("delete-task", {"task_id": task_a}, approval_token=minted.credential)
    if not isinstance(first, CommandSuccess):
        _fail(f"first execution expected to succeed; got {type(first).__name__}")
        return False
    _ok("First execution succeeded")

    new_task = store.create(title="replay target")
    _step(f"Attacker captures the credential and tries to delete task_id={new_task['task_id']}")
    replay = dispatcher.execute(
        "delete-task", {"task_id": new_task["task_id"]}, approval_token=minted.credential
    )
    if not isinstance(replay, ApprovalRequired):
        _fail(f"replay expected to be rejected; got {type(replay).__name__}")
        return False
    _rejected("Dispatcher refused the replay", reason=replay.reason or "")
    return True


def scenario_translation_round_trip() -> bool:
    """Pattern 1: A2A↔MCP protocol translation.

    Walks the (authorization_details, context_id, binding_message) tuple
    through both translation directions and asserts the round-trip
    preserves the round-trip properties. Companion to the Pattern-2
    scenarios above; together they cover both of the bridge's
    publishable patterns.
    """
    _header("Pattern 1: A2A↔MCP translation round-trip")

    authorization_details = {
        "type": RAR_TYPE,
        "command": "delete-task",
        "args": {"task_id": "task-42"},
    }
    a2a_event = A2aAuthRequiredEvent(
        task_id="task-001",
        context_id="ctx-abc123",
        authorization_details=authorization_details,
        binding_message="Delete the Q2 launch checklist?",
    )
    _step("A2A: agent emits task_status_update state=auth_required")

    mcp_request = a2a_auth_required_to_mcp_elicitation(
        a2a_event, bridge_base_url="https://bridge.example",
    )
    if mcp_request.mode != "url":
        _fail(f"expected url-mode elicitation, got {mcp_request.mode!r}")
        return False
    _ok(f"Bridge translated to MCP elicitation (mode={mcp_request.mode}, "
        f"elicitation_id={mcp_request.elicitation_id})")

    if mcp_request.authorization_details is not authorization_details:
        _fail("authorization_details was not forwarded byte-identical")
        return False
    _ok("authorization_details forwarded byte-identical - signer sees what agent proposed")

    _step("Human (via MCP host) approves and signs")
    signed = sign_authorization_details(
        command=a2a_event.authorization_details["command"],
        args=a2a_event.authorization_details["args"],
        rar_type=a2a_event.authorization_details["type"],
        approver_id="alice@example.com",
        binding_message=a2a_event.binding_message,
        secret=USER_SECRET,
    )

    _step("MCP host returns elicitation/response (accept) with signed payload")
    mcp_response = McpElicitationResponse(
        elicitation_id=mcp_request.elicitation_id,
        action="accept",
        signed_payload={
            "command": signed.command, "args": signed.args, "rar_type": signed.rar_type,
            "exp": signed.exp, "approver_id": signed.approver_id, "signature": signed.signature,
        },
    )

    a2a_resume = mcp_elicitation_response_to_a2a_resume(mcp_response)
    if a2a_resume.context_id != a2a_event.context_id:
        _fail(f"context_id continuity broken: {a2a_resume.context_id!r} != "
              f"{a2a_event.context_id!r}")
        return False
    _ok(f"Bridge translated back to A2A resume "
        f"(context_id={a2a_resume.context_id} round-tripped intact)")

    if not a2a_resume.approved:
        _fail("a resume from action=accept must yield approved=True")
        return False
    _ok("approved=True; A2A executor can now unblock its HITL gate")
    return True


def scenario_authority_key_isolation() -> bool:
    """Tier 2: delegation authority-to-delegation authority key isolation.

    Demonstrates a *narrow* property: a JWT minted by one OAuthAuthority
    instance does not validate at a different OAuthAuthority instance whose
    mint_secret differs. The dispatcher refuses with SignatureMismatch.

    This is NOT a demonstration of Zero Trust under agent compromise.
    The realistic agent-process-compromise adversary (in the HS256
    reference) holds BOTH the user signing secret AND the mint secret,
    because the demo configuration co-locates them. That stronger
    property is tested in
    tests/e2e/test_dispatcher_authority_integration.py::
    test_tier2_attacker_without_user_secret_cannot_forge_a_new_signature.

    This scenario is published as evidence of cross-delegation authority key
    independence, useful when a single delegation authority deployment hosts multiple
    isolated trust domains.
    """
    _header("Tier 2: delegation authority-to-delegation authority key isolation")
    store, task_a, _ = _seed_two_tasks()

    legit_authority = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret=MINT_SECRET, expected_rar_type=RAR_TYPE,
    )
    other_authority = OAuthAuthority(
        user_signing_secret=USER_SECRET, mint_secret="DIFFERENT-AUTHORITY-MINT-SECRET-32-BYTES-PAD", expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=store, authority=legit_authority)

    _step("A different delegation authority instance (different mint_secret) signs a token for this action")
    signed = sign_authorization_details(
        command="delete-task", args={"task_id": task_a}, rar_type=RAR_TYPE,
        approver_id="alice", binding_message=f"Delete task {task_a}?",
        secret=USER_SECRET,
    )
    other_credential = other_authority.mint(signed)
    _ok("Foreign-delegation authority mint produced a structurally-valid JWT")

    _step("Foreign-delegation authority JWT presented to the dispatcher backed by the LEGITIMATE delegation authority")
    outcome = dispatcher.execute(
        "delete-task", {"task_id": task_a}, approval_token=other_credential.credential
    )
    if not isinstance(outcome, ApprovalRequired):
        _fail("dispatcher accepted a JWT from a foreign delegation authority - key isolation broken")
        return False
    _rejected("Dispatcher refused the foreign-delegation authority JWT", reason=outcome.reason or "")
    if task_a not in {t["task_id"] for t in store.list()}:
        _fail("foreign-delegation authority JWT caused a delete")
        return False
    _ok("Task survives - cross-delegation authority key isolation holds")
    return True


# ── Scenario dispatcher ─────────────────────────────────────────────────────


_SCENARIOS: dict[str, Callable[[argparse.Namespace], bool]] = {
    "tier1":          lambda a: scenario_full_flow(tier=1),
    "tier2":          lambda a: scenario_full_flow(tier=2),
    "drift":          lambda a: scenario_parameter_drift(tier=a.tier),
    "replay":         lambda a: scenario_replay(tier=a.tier),
    "key-isolation":  lambda a: scenario_authority_key_isolation(),
    "translation":    lambda a: scenario_translation_round_trip(),
}


def _run_all(args: argparse.Namespace) -> bool:
    results: list[tuple[str, bool]] = []
    for tier in (1, 2):
        results.append((f"tier{tier} full flow", scenario_full_flow(tier=tier)))
        results.append((f"tier{tier} drift", scenario_parameter_drift(tier=tier)))
        results.append((f"tier{tier} replay", scenario_replay(tier=tier)))
    results.append(("tier2 key-isolation", scenario_authority_key_isolation()))
    results.append(("pattern-1 translation", scenario_translation_round_trip()))

    _header("Summary")
    for name, ok in results:
        _outcome_summary(name, ok)
    return all(ok for _, ok in results)


# ── argparse ────────────────────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="actionauth",
        description="ActionAuth: functional smoke-test CLI.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    demo = sub.add_parser("demo", help="run a HITL-flow scenario end-to-end")
    demo_sub = demo.add_subparsers(dest="scenario", required=True)

    for name in ("tier1", "tier2"):
        demo_sub.add_parser(name, help=f"full happy-path flow on {name}")

    for name in ("drift", "replay"):
        p = demo_sub.add_parser(name, help=f"{name} scenario")
        p.add_argument("--tier", type=int, choices=(1, 2), default=1,
                       help="which delegation authority tier to exercise (default: 1)")

    demo_sub.add_parser("key-isolation",
                        help="Tier-2: JWT minted by one delegation authority does not validate at another (narrow property)")
    demo_sub.add_parser("translation",
                        help="Pattern 1: A2A↔MCP protocol translation round-trip")
    demo_sub.add_parser("all", help="run every scenario and summarise")

    walk = sub.add_parser(
        "walkthrough",
        help="step-by-step simulation of the sequence diagram in `docs/architecture.md`",
    )
    walk.add_argument("--tier", type=int, choices=(1, 2), default=2,
                      help="which delegation authority tier to walk through (default: 2)")
    walk.add_argument("--pause", action="store_true",
                      help="wait for Enter between steps (useful for live demos)")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)

    if args.cmd == "walkthrough":
        from actionauth.walkthrough import walkthrough_a2a
        return walkthrough_a2a(tier=args.tier, pause=args.pause)

    if args.cmd != "demo":
        return 2

    if args.scenario == "all":
        return 0 if _run_all(args) else 1

    runner = _SCENARIOS.get(args.scenario)
    if runner is None:
        print(f"unknown scenario: {args.scenario}", file=sys.stderr)
        return 2

    return 0 if runner(args) else 1


if __name__ == "__main__":
    raise SystemExit(main())
