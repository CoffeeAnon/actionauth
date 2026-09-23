"""End-to-end composition test for the MCP HITL flow's *building blocks*.

**Scope:** this test composes the translation dataclasses, the
consent server, the delegation authority, and the RS *by hand* - it does not drive the
MCP server's ``tools/call`` wire. That wire IS now bundled: the
single-agent emission + resume path through the real MCP server is
exercised by ``tests/e2e/test_mcp_elicitation_emission.py`` (and the
``McpHitlGate`` primitive by ``tests/unit/test_mcp_hitl_gate.py``). This
test remains as the by-hand composition of the same building blocks - it
shows the pieces compose independently of the server harness.

What this test proves:

  - The translation module's two functions compose correctly:
    A2A `auth_required` → MCP elicitation request → MCP elicitation
    response → A2A resume.
  - The consent server's three endpoints (render, submit, result)
    correctly intermediate the human-in-the-loop step.
  - The delegation authority's mint + the RS's consume operate on the building
    blocks' outputs without further glue.

What this test does NOT prove:

  - That a real MCP host calling `tools/call delete_task` would
    receive an `elicitation/create` event from `build_mcp_app` and
    route through this flow end-to-end. That wiring is the
    documented "next step"; the building blocks are here so a
    downstream implementer can compose them with the MCP SDK's
    elicitation primitives.

Requires `pip install -e '.[mcp]'`.
"""
import pytest

starlette = pytest.importorskip("starlette")
from starlette.testclient import TestClient  # noqa: E402

from actionauth.consent.url_mode import ConsentStore, build_consent_app  # noqa: E402
from actionauth.core.client import InMemoryTaskStore  # noqa: E402
from actionauth.rs import JwtResourceServer, RsSuccess  # noqa: E402
from actionauth.translation import (  # noqa: E402
    A2aAuthRequiredEvent,
    McpElicitationResponse,
    a2a_auth_required_to_mcp_elicitation,
    mcp_elicitation_response_to_a2a_resume,
)
from actionauth.authority import (  # noqa: E402
    OAuthAuthority,
    SignedAuthorizationDetails,
)


USER_SECRET = "mcp-roundtrip-user-secret-32bytes-pad"
MINT_SECRET = "mcp-roundtrip-mint-secret-32bytes-padxx"
ISSUER = "https://authority.reference.invalid"
AUDIENCE = "bridge-resource-server"
RAR_TYPE = "tasktracker_task_action"
BRIDGE_BASE_URL = "https://bridge.example"


@pytest.fixture
def world():
    """Full Tier-2 setup: store + delegation authority + RS + consent server + TestClient."""
    store = InMemoryTaskStore()
    target = store.create(title="Q2 launch checklist")
    bystander = store.create(title="Q3 onboarding doc")

    authority = OAuthAuthority(
        user_signing_secret=USER_SECRET,
        mint_secret=MINT_SECRET,
        issuer=ISSUER,
        audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
    )
    rs = JwtResourceServer(
        verification_secret=MINT_SECRET,
        expected_issuer=ISSUER,
        expected_audience=AUDIENCE,
        expected_rar_type=RAR_TYPE,
        client=store,
    )
    consent_store = ConsentStore()
    consent_client = TestClient(
        build_consent_app(store=consent_store, user_signing_secret=USER_SECRET),
    )
    return {
        "store": store, "target": target, "bystander": bystander,
        "authority": authority, "rs": rs,
        "consent_store": consent_store, "consent_client": consent_client,
    }


def test_mcp_hitl_building_blocks_happy_path(world):
    """The translation + consent + delegation authority + RS building blocks compose
    correctly. NOT a proof that the MCP server emits the elicitation
    in production - that's the unbundled next step."""
    target = world["target"]
    bystander = world["bystander"]

    # 1. Agent dispatch hits HITL gate. Bridge builds authorization_details.
    authorization_details = {
        "type": RAR_TYPE,
        "command": "delete-task",
        "args": {"task_id": target["task_id"]},
    }

    # 2. Bridge translates A2A `auth_required` envelope → MCP elicitation.
    a2a_event = A2aAuthRequiredEvent(
        task_id="task-001",
        context_id="ctx-mcp-test",
        authorization_details=authorization_details,
        binding_message=f"Delete '{target['title']}'?",
    )
    mcp_request = a2a_auth_required_to_mcp_elicitation(
        a2a_event, bridge_base_url=BRIDGE_BASE_URL,
    )
    assert mcp_request.mode == "url"

    # 3. Bridge mints a consent session and emits the URL to the MCP host.
    consent_req = world["consent_store"].create(
        command=authorization_details["command"],
        args=authorization_details["args"],
        rar_type=RAR_TYPE,
        approver_id="alice@example.com",
        binding_message=a2a_event.binding_message,
    )

    # 4. User visits the consent URL - page renders the action.
    page = world["consent_client"].get(f"/consent/{consent_req.session_id}")
    assert page.status_code == 200
    assert "delete-task" in page.text
    assert target["task_id"] in page.text
    assert target["title"] in page.text

    # 5. User approves; consent server captures the signed payload.
    submit = world["consent_client"].post(
        f"/consent/{consent_req.session_id}/submit",
        data={"decision": "approve"},
    )
    assert submit.status_code == 200

    # 6. Bridge polls the consent server for the result.
    poll = world["consent_client"].get(f"/consent/{consent_req.session_id}/result")
    assert poll.status_code == 200
    signed_dict = poll.json()["signed"]

    # 7. Bridge constructs the MCP elicitation response and translates back.
    mcp_response = McpElicitationResponse(
        elicitation_id=mcp_request.elicitation_id,
        action="accept",
        signed_payload=signed_dict,
    )
    a2a_resume = mcp_elicitation_response_to_a2a_resume(mcp_response)
    assert a2a_resume.approved
    assert a2a_resume.context_id == a2a_event.context_id  # round-trip continuity

    # 8. Bridge presents the signed RAR to the delegation authority → mint credential.
    signed = SignedAuthorizationDetails(
        command=signed_dict["command"],
        args=signed_dict["args"],
        rar_type=signed_dict["rar_type"],
        exp=signed_dict["exp"],
        approver_id=signed_dict["approver_id"],
        binding_message=signed_dict["binding_message"],
        signature=signed_dict["signature"],
    )
    minted = world["authority"].mint(signed)

    # 9. Bridge forwards the credential to the RS → validate + execute.
    outcome = world["rs"].execute(
        signed.command, signed.args, minted.credential,
    )
    assert isinstance(outcome, RsSuccess)

    # 10. Post-condition: target deleted, bystander survives.
    remaining = {t["task_id"] for t in world["store"].list()}
    assert target["task_id"] not in remaining
    assert bystander["task_id"] in remaining


def test_mcp_hitl_building_blocks_user_denies(world):
    """User declines at the consent page → bridge resumes with rejection."""
    target = world["target"]

    consent_req = world["consent_store"].create(
        command="delete-task",
        args={"task_id": target["task_id"]},
        rar_type=RAR_TYPE,
        approver_id="alice@example.com",
        binding_message=f"Delete '{target['title']}'?",
    )

    world["consent_client"].post(
        f"/consent/{consent_req.session_id}/submit",
        data={"decision": "deny"},
    )
    result = world["consent_client"].get(f"/consent/{consent_req.session_id}/result")
    assert result.json()["status"] == "denied"

    # Bridge would translate this denial into an A2A resume with approved=False.
    # Mint a tag-verified elicitation_id via the public translator.
    _eid_req = a2a_auth_required_to_mcp_elicitation(
        A2aAuthRequiredEvent(
            task_id="task-001",
            context_id="ctx-x",
            authorization_details={"command": "delete-task", "args": {"task_id": target["task_id"]}},
            binding_message="m",
        ),
        bridge_base_url="https://bridge.example",
    )
    mcp_response = McpElicitationResponse(
        elicitation_id=_eid_req.elicitation_id,
        action="decline",
        signed_payload=None,
    )
    a2a_resume = mcp_elicitation_response_to_a2a_resume(mcp_response)
    assert not a2a_resume.approved
    assert a2a_resume.rejection_reason == "decline"

    # Post-condition: target survives.
    assert target["task_id"] in {t["task_id"] for t in world["store"].list()}
