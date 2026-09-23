"""Tests for the A2A↔MCP translation adapter (Pattern 1).

These tests are the executable counterpart to the "orchestration
contribution" in ``docs/rationale.md`` — they prove the translation preserves
the load-bearing properties (context_id continuity,
authorization_details byte-identity, URL-mode for sensitive consent)
through pure-data transformations, no network.
"""
import pytest

from actionauth.translation import (
    A2aAuthRequiredEvent,
    A2aResumeMessage,
    McpElicitationRequest,
    McpElicitationResponse,
    TranslationError,
    a2a_auth_required_to_mcp_elicitation,
    mcp_elicitation_response_to_a2a_resume,
)


# ── Sample inputs ─────────────────────────────────────────────────────────


_AD = {
    "type": "tasktracker_task_action",
    "command": "delete-task",
    "args": {"task_id": "t-42"},
}

_EVENT = A2aAuthRequiredEvent(
    task_id="task-001",
    context_id="ctx-abc123",
    authorization_details=_AD,
    binding_message="Delete the task titled 'Q2 launch checklist'?",
)


def _valid_eid_for(event: A2aAuthRequiredEvent = _EVENT) -> str:
    """Mint a tag-verified elicitation_id via the public translator.

    Elicitation IDs include a process-local HMAC tag, so tests that
    need to assert on the resume side must obtain IDs through the
    minting path rather than hard-coding strings.
    """
    return a2a_auth_required_to_mcp_elicitation(
        event, bridge_base_url="https://bridge.example",
    ).elicitation_id


# ── Direction 1: A2A → MCP ────────────────────────────────────────────────


def test_a2a_to_mcp_basic_translation():
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example/")
    assert isinstance(req, McpElicitationRequest)
    assert req.mode == "url"
    assert req.title == "Approve agent action"
    assert req.description == _EVENT.binding_message


def test_a2a_to_mcp_url_mode_required_by_spec():
    """Per MCP 2025-11-25: sensitive consent MUST use url mode, not form."""
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example")
    assert req.mode == "url"


def test_a2a_to_mcp_url_points_at_bridge_consent_server():
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example/")
    assert req.url.startswith("https://bridge.example/consent/")
    # Trailing slash on base_url must not double up.
    req2 = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example")
    assert req2.url == req.url


def test_a2a_to_mcp_authorization_details_byte_identical():
    """Load-bearing: the bridge MUST NOT re-canonicalise authorization_details.

    The human will sign over the same bytes the agent proposed. If the
    bridge reorders keys or normalises values, the signature won't match.
    """
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example")
    assert req.authorization_details is _EVENT.authorization_details  # same object reference
    assert req.authorization_details == _AD


def test_a2a_to_mcp_elicitation_id_encodes_context_for_routing():
    """The elicitation_id must round-trip back to the original context_id
    so the eventual response can be routed to the paused task."""
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example")
    assert "ctx-abc123" in req.elicitation_id
    assert "task-001" in req.elicitation_id


def test_a2a_to_mcp_rejects_empty_context_id():
    bad = A2aAuthRequiredEvent(
        task_id="task-001", context_id="",
        authorization_details=_AD, binding_message="m",
    )
    with pytest.raises(TranslationError, match="context_id"):
        a2a_auth_required_to_mcp_elicitation(bad, bridge_base_url="https://bridge.example")


def test_a2a_to_mcp_rejects_colon_in_context_id():
    """Defense: the elicitation_id shape `el:<context>:<task>` uses
    ``:`` as a separator. A context_id containing ``:`` would silently
    corrupt the round-trip parse. Reject explicitly instead of
    materialising the bug as "wrong task resumed" later.
    """
    bad = A2aAuthRequiredEvent(
        task_id="task-001",
        context_id="urn:uuid:abc",   # legit-looking but contains colons
        authorization_details=_AD,
        binding_message="m",
    )
    with pytest.raises(TranslationError, match="context_id must not contain"):
        a2a_auth_required_to_mcp_elicitation(bad, bridge_base_url="https://bridge.example")


def test_a2a_to_mcp_rejects_colon_in_task_id():
    bad = A2aAuthRequiredEvent(
        task_id="ns:task-001",
        context_id="ctx-abc",
        authorization_details=_AD,
        binding_message="m",
    )
    with pytest.raises(TranslationError, match="task_id must not contain"):
        a2a_auth_required_to_mcp_elicitation(bad, bridge_base_url="https://bridge.example")


def test_a2a_to_mcp_rejects_non_dict_authorization_details():
    bad = A2aAuthRequiredEvent(
        task_id="task-001", context_id="c",
        authorization_details="not-a-dict",  # type: ignore[arg-type]
        binding_message="m",
    )
    with pytest.raises(TranslationError, match="authorization_details"):
        a2a_auth_required_to_mcp_elicitation(bad, bridge_base_url="https://bridge.example")


# ── Direction 2: MCP → A2A ────────────────────────────────────────────────


_SIGNED = {
    "command": "delete-task",
    "args": {"task_id": "t-42"},
    "rar_type": "tasktracker_task_action",
    "exp": 1779315522,
    "approver_id": "alice@example.com",
    "signature": "deadbeef" * 8,
}


def test_mcp_to_a2a_accept_translates_to_approved():
    resp = McpElicitationResponse(
        elicitation_id=_valid_eid_for(),
        action="accept",
        signed_payload=_SIGNED,
    )
    msg = mcp_elicitation_response_to_a2a_resume(resp)
    assert isinstance(msg, A2aResumeMessage)
    assert msg.approved is True
    assert msg.context_id == "ctx-abc123"
    assert msg.signed_payload is _SIGNED   # byte-identical forwarding
    assert msg.rejection_reason is None


def test_mcp_to_a2a_decline_translates_to_rejected():
    resp = McpElicitationResponse(
        elicitation_id=_valid_eid_for(),
        action="decline",
        signed_payload=None,
    )
    msg = mcp_elicitation_response_to_a2a_resume(resp)
    assert msg.approved is False
    assert msg.rejection_reason == "decline"
    assert msg.signed_payload is None


def test_mcp_to_a2a_cancel_treated_as_decline():
    resp = McpElicitationResponse(
        elicitation_id=_valid_eid_for(),
        action="cancel",
        signed_payload=None,
    )
    msg = mcp_elicitation_response_to_a2a_resume(resp)
    assert msg.approved is False
    assert msg.rejection_reason == "cancel"


def test_mcp_to_a2a_accept_without_signed_payload_is_error():
    """Accept with no signed_payload is a malformed message — the
    bridge cannot resume an A2A task without proof of consent."""
    resp = McpElicitationResponse(
        elicitation_id=_valid_eid_for(), action="accept", signed_payload=None,
    )
    with pytest.raises(TranslationError, match="signed_payload"):
        mcp_elicitation_response_to_a2a_resume(resp)


def test_mcp_to_a2a_unknown_action_rejected():
    resp = McpElicitationResponse(
        elicitation_id=_valid_eid_for(), action="approve_maybe", signed_payload=None,
    )
    with pytest.raises(TranslationError, match="unknown.*action"):
        mcp_elicitation_response_to_a2a_resume(resp)


def test_mcp_to_a2a_malformed_elicitation_id_rejected():
    """Elicitation IDs are minted by us; unexpected shape means tampering
    or programming error. The shape is now ``el:<ctx>:<task>:<tag>`` with
    an HMAC tag; missing parts, missing fields, or bad tags all reject.
    """
    bad_ids = (
        "not-our-format",
        "el:only_one_part",
        "el::missing-context",
        # Right shape, but no HMAC tag at all.
        "el:ctx-abc123:task-001",
        # Right shape and tag positions, but the tag is junk.
        "el:ctx-abc123:task-001:not-a-valid-tag-AAAAAAAAAAAAAAAAAAAAAAA",
    )
    for bad_id in bad_ids:
        resp = McpElicitationResponse(
            elicitation_id=bad_id, action="decline", signed_payload=None,
        )
        with pytest.raises(TranslationError):
            mcp_elicitation_response_to_a2a_resume(resp)


def test_mcp_to_a2a_rejects_forged_elicitation_id_with_guessed_ids():
    """Elicitation-ID forgery resistance: an attacker who guesses or
    learns (context_id, task_id) but does not hold the bridge's tag
    secret cannot forge a valid elicitation_id. Crafting
    ``el:<ctx>:<task>:<arbitrary_tag>`` is rejected at parse time.
    """
    import base64
    # Bogus tag of correct byte length (32 random bytes b64url-encoded).
    bogus_tag = base64.urlsafe_b64encode(b"\x00" * 32).decode().rstrip("=")
    forged = f"el:ctx-abc123:task-001:{bogus_tag}"
    resp = McpElicitationResponse(
        elicitation_id=forged, action="decline", signed_payload=None,
    )
    with pytest.raises(TranslationError, match="tag does not verify"):
        mcp_elicitation_response_to_a2a_resume(resp)


# ── Round-trip: A2A → MCP → MCP-response → A2A-resume ─────────────────────


def test_round_trip_context_id_continuity():
    """Pattern-1 property: the bridge preserves context_id across the
    A2A → MCP → A2A round-trip. The agent's paused task can be resumed
    via the same context_id that was paused."""
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example")
    # Simulate the human signing and MCP host responding.
    resp = McpElicitationResponse(
        elicitation_id=req.elicitation_id, action="accept", signed_payload=_SIGNED,
    )
    msg = mcp_elicitation_response_to_a2a_resume(resp)
    assert msg.context_id == _EVENT.context_id


def test_round_trip_authorization_details_unchanged():
    """The authorization_details the human signs over is byte-identical
    to what the agent proposed. The bridge does not re-canonicalise."""
    req = a2a_auth_required_to_mcp_elicitation(_EVENT, bridge_base_url="https://bridge.example")
    assert req.authorization_details == _EVENT.authorization_details
    # And the signature value (in real flow) would be over those same bytes.
