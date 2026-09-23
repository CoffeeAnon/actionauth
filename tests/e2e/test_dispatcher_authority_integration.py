"""End-to-end: dispatcher + delegation authority on both tiers.

These tests exercise the full path from "human signs an authorization-
details payload" through "delegation authority mints a credential" to "dispatcher
consumes the credential and executes the action." Both tiers are
tested through the same dispatcher API, demonstrating that swapping
Tier 1 for Tier 2 is purely a delegation authority implementation swap.
"""
import pytest

from actionauth.core.client import InMemoryTaskStore
from actionauth.core.dispatcher import (
    ApprovalRequired,
    CommandSuccess,
    Dispatcher,
)
from actionauth.authority import (
    InProcessAuthority,
    OAuthAuthority,
    sign_authorization_details,
)


USER_SECRET = "user-secret-32bytes-minimum-padding-x"
MINT_SECRET = "mint-secret-32bytes-minimum-padding-x"
RAR_TYPE = "tasktracker_task_action"


def _signed(command, args, secret=USER_SECRET):
    return sign_authorization_details(
        command=command,
        args=args,
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=f"{command} {args}",
        secret=secret,
    )


@pytest.fixture
def seeded_client():
    client = InMemoryTaskStore()
    a = client.create(title="A: promised for deletion")
    b = client.create(title="B: must survive drift attempts")
    return client, a["task_id"], b["task_id"]


# ── Tier 1: InProcessAuthority ─────────────────────────────────────────────────


def test_tier1_full_flow_deletes_approved_task(seeded_client):
    client, promised_id, drift_id = seeded_client
    authority = InProcessAuthority(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, authority=authority)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = authority.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert isinstance(outcome, CommandSuccess)
    remaining = {t["task_id"] for t in client.list()}
    assert promised_id not in remaining
    assert drift_id in remaining


def test_tier1_drift_attempt_does_not_execute(seeded_client):
    client, promised_id, drift_id = seeded_client
    authority = InProcessAuthority(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, authority=authority)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = authority.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": drift_id}, approval_token=minted.credential)
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "CredentialDrift"
    # Both tasks survive.
    remaining = {t["task_id"] for t in client.list()}
    assert promised_id in remaining
    assert drift_id in remaining


def test_tier1_replay_attempt_does_not_execute(seeded_client):
    client, promised_id, _ = seeded_client
    authority = InProcessAuthority(secret=USER_SECRET, expected_rar_type=RAR_TYPE)
    dispatcher = Dispatcher(client=client, authority=authority)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = authority.mint(signed)

    # Create a second task with the same id-value to make the test deterministic.
    # First consumption succeeds:
    first = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert isinstance(first, CommandSuccess)

    # Replay: re-create the task to give the second consume something to attempt,
    # then submit the same credential. delegation authority refuses.
    new_task = client.create(title="replay target")
    replay = dispatcher.execute("delete-task", {"task_id": new_task["task_id"]}, approval_token=minted.credential)
    assert isinstance(replay, ApprovalRequired)
    assert replay.reason in ("CredentialReplay", "CredentialDrift")


# ── Tier 2: OAuthAuthority ─────────────────────────────────────────────────────


def test_tier2_full_flow_deletes_approved_task(seeded_client):
    client, promised_id, drift_id = seeded_client
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=client, authority=authority)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = authority.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": promised_id}, approval_token=minted.credential)
    assert isinstance(outcome, CommandSuccess)


def test_tier2_drift_attempt_does_not_execute(seeded_client):
    client, promised_id, drift_id = seeded_client
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=client, authority=authority)

    signed = _signed("delete-task", {"task_id": promised_id})
    minted = authority.mint(signed)

    outcome = dispatcher.execute("delete-task", {"task_id": drift_id}, approval_token=minted.credential)
    assert isinstance(outcome, ApprovalRequired)
    assert outcome.reason == "CredentialDrift"


def test_tier2_attacker_without_user_secret_cannot_forge_a_new_signature(seeded_client):
    """*** Zero-Trust property in test form (production-shape only). ***

    Honest scope: this test models the **production** Tier-2 deployment
    where the user signing key lives client-side (WebAuthn / Passkey)
    and the actionauth/agent process never holds it. In the **HS256 demo
    configuration** the bridge process holds *both* secrets and an
    attacker with code execution there has both; that case is NOT
    what this test covers. See README "Architectural boundaries and production gaps" and the
    docs/architecture.md threat-model row "Compromised agent process"
    for the demo-mode caveat.

    Production-shape threat model: the attacker has compromised the
    agent process and therefore holds whatever the agent's process
    holds; the user signing key lives on the human's MCP host
    (WebAuthn, Passkey, or equivalent), NOT on the agent. The attacker
    can re-use *previously-signed* payloads (within their TTL) but
    cannot forge a signature for an action the human did not approve.

    This test demonstrates that asymmetry: the simulated attacker has
    the captured signed payload for "delete task A" and tries to
    alter its `args` to "delete task B" (mutating the dataclass field
    while leaving the signature intact). The delegation authority refuses to mint
    because the signature does not verify over the mutated payload.

    Note on the demo-mode caveat: when run end-to-end inside *this
    test process*, both secrets are in memory. The test does not give
    the simulated attacker `USER_SECRET`; it gives it the
    `SignedAuthorizationDetails` object that was produced earlier
    and tries to forge by mutation. The realistic attacker in the
    HS256 co-located demo would simply call `sign_authorization_details`
    with the user secret directly, and the property would fail; the
    HS256 reference is honest about that in the docs.
    """
    client, promised_id, drift_id = seeded_client
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )
    dispatcher = Dispatcher(client=client, authority=authority)

    # Step 1: human signs for promised_id and approves.
    human_signed = _signed("delete-task", {"task_id": promised_id})

    # Step 2: agent-process attacker captures this signed payload (it
    # traverses the agent on its way to the delegation authority). The attacker now
    # tries to mint a credential for a different task.
    from dataclasses import replace
    forged_for_different_task = replace(human_signed, args={"task_id": drift_id})
    # The signature is now mismatched against the args (still over the
    # original promised_id payload). The delegation authority refuses to mint.
    from actionauth.authority.interface import SignatureMismatch
    with pytest.raises(SignatureMismatch):
        authority.mint(forged_for_different_task)

    # Step 3: nothing was minted; nothing was executed.
    assert promised_id in {t["task_id"] for t in client.list()}
    assert drift_id in {t["task_id"] for t in client.list()}


def test_tier2_captured_signed_payload_cannot_be_reminted(seeded_client):
    """Consent Atomicity: one human signature exchanges for at most one
    credential. An attacker who captures the human's signed payload
    (leaked WebSocket frame, compromised relay, compromised bridge
    process) cannot replay it to mint a second credential, even within
    the signed-payload TTL.

    Closes the multi-mint surface that earlier revisions of this
    reference left open as a documented carve-out. The delegation authority now tracks
    canonical-bytes hashes of signed payloads accepted at mint and
    raises ``SignatureReplay`` on the second presentation. The contract
    is "fresh consent per execution", not just "fresh consent per
    action shape."

    See ``actionauth/authority/oauth.py``'s ``_consumed_signatures`` and the
    ``SignatureReplay`` docstring in ``actionauth/authority/interface.py``.
    """
    from actionauth.authority.interface import SignatureReplay

    client, promised_id, _ = seeded_client
    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        expected_rar_type=RAR_TYPE,
    )

    signed = _signed("delete-task", {"task_id": promised_id})
    first_credential = authority.mint(signed)

    # Second presentation of the same signed payload is refused. The
    # human signed once; only one credential exists.
    with pytest.raises(SignatureReplay):
        authority.mint(signed)

    # The first credential still works (the closure is at mint, not at
    # consume - a legitimately minted credential is unaffected).
    assert first_credential.jti
