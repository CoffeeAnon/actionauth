"""McpHitlGate - the single-agent HITL emission/resume primitive.

The gate is what the MCP server's call-tool handler uses to turn a
dispatcher ``ApprovalRequired`` outcome into a URL-mode elicitation, and
to resume once the human has approved at the consent server. It is the
single-agent (no-A2A) analogue of the A2A↔MCP translation: same delegation authority
core, no second agent, just MCP elicitation + an independent consent
surface.

Tested with real components (ConsentStore, InProcessAuthority, the demo
signer) - no mocks.
"""
import pytest

pytest.importorskip("mcp")

from pathlib import Path  # noqa: E402

from mcp import types as mcp_types  # noqa: E402

from actionauth.consent.url_mode import ConsentStore  # noqa: E402
from actionauth.consent.demo_signer import demo_sign_as_user  # noqa: E402
from actionauth.mcp.hitl import McpHitlGate  # noqa: E402
from actionauth.authority import InProcessAuthority  # noqa: E402


SECRET = "mcp-hitl-gate-secret-32bytes-minimum-x"
RAR_TYPE = "tasktracker_task_action"
_REPO_ROOT = Path(__file__).resolve().parents[2]


def _gate(store=None, authority=None):
    return McpHitlGate(
        consent_store=store or ConsentStore(),
        bridge_base_url="https://bridge.example",
        rar_type=RAR_TYPE,
        authority=authority,
    )


def test_begin_creates_consent_session_and_returns_url_elicitation():
    store = ConsentStore()
    gate = _gate(store=store)

    params = gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )

    assert isinstance(params, mcp_types.ElicitRequestURLParams)
    assert params.mode == "url"
    assert params.url.endswith(f"/consent/{params.elicitation_id}")
    # A consent session exists for that id, carrying the exact action.
    req = store.get(params.elicitation_id)
    assert req is not None
    assert req.command == "delete-task"
    assert dict(req.args) == {"task_id": "t-42"}


def test_try_resume_returns_none_before_approval():
    store = ConsentStore()
    gate = _gate(store=store, authority=InProcessAuthority(secret=SECRET))
    gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )
    # Human has not approved at the consent surface yet.
    token = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    assert token is None


def _approve(store, params, *, command, args, binding_message):
    """Simulate the human approving at the consent surface (demo signs
    server-side, exactly as the consent server's submit endpoint does)."""
    signed = demo_sign_as_user(
        command=command,
        args=args,
        rar_type=RAR_TYPE,
        approver_id="alice",
        binding_message=binding_message,
        user_secret=SECRET,
    )
    assert store.submit_signed(params.elicitation_id, signed)


def test_try_resume_mints_credential_after_approval():
    store = ConsentStore()
    authority = InProcessAuthority(secret=SECRET)
    gate = _gate(store=store, authority=authority)
    params = gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )

    _approve(store, params, command="delete-task", args={"task_id": "t-42"},
             binding_message="Delete task t-42?")

    token = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    assert token is not None
    # The minted credential validates at the same delegation authority for the approved action.
    consumed = authority.consume(token, "delete-task", {"task_id": "t-42"})
    assert consumed.command == "delete-task"


def test_try_resume_is_idempotent_after_mint():
    """A second resume of an already-minted approval returns the same token
    rather than re-minting (which the delegation authority's SignatureReplay would reject)."""
    store = ConsentStore()
    authority = InProcessAuthority(secret=SECRET)
    gate = _gate(store=store, authority=authority)
    params = gate.begin(
        command="delete-task",
        args={"task_id": "t-42"},
        caller_id="alice",
        binding_message="Delete task t-42?",
    )
    _approve(store, params, command="delete-task", args={"task_id": "t-42"},
             binding_message="Delete task t-42?")

    first = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    second = gate.try_resume(command="delete-task", args={"task_id": "t-42"}, caller_id="alice")
    assert first is not None
    assert first == second


# ---------------------------------------------------------------------------
# Minted-credential-at-rest documentation
#
# The cache deliberately stores the bearer token in the plaintext `command`
# slot of the shared durable state. That is a reference-implementation
# choice, not a production pattern. The notice is the deliverable here: a
# porting engineer must see it in BOTH the code (where they will copy the
# call) and the README (where they read the threat model). Both tests fail
# if either notice is silently stripped.
# ---------------------------------------------------------------------------

def test_minted_credential_cache_put_carries_at_rest_security_notice():
    """`_MintedCredentialCache.put` stores the bearer token in the plaintext
    `command` slot. The docstring at that site must name the at-rest
    security property so a porting engineer does not copy the pattern
    unknowingly.

    Asserts the notice is present and says the three things that matter:
    (1) the token is stored unencrypted, (2) this is acceptable only because
    the repo is a reference implementation, (3) a production port must use
    encrypted-at-rest storage. Fails if the docstring is removed or reduced
    to a generic one-liner.
    """
    from actionauth.mcp import hitl as hitl_mod

    put_fn = hitl_mod._MintedCredentialCache.put
    doc = put_fn.__doc__ or ""
    # The three required statements, checked as distinct substrings so the
    # test fails on any one being dropped, not just the whole docstring.
    assert "unencrypted" in doc.lower(), "must state the token is stored unencrypted"
    assert "reference implementation" in doc.lower(), \
        "must scope the acceptability to the reference implementation"
    assert "encrypted-at-rest" in doc.lower(), \
        "must require encrypted-at-rest storage for a production port"
    # And it must actually describe the overload, not just the words.
    assert "command" in doc.lower(), "must name the overloaded `command` slot"


def test_readme_documents_credential_at_rest():
    """The README's durable-state section must carry the at-rest caveat, so
    the threat model is discoverable by someone reading the docs (not just
    the code). Fails if the README note is stripped.
    """
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    # The note must exist and carry the four required statements.
    assert "unencrypted" in readme.lower(), "README must state the token is unencrypted at rest"
    assert "encrypted-at-rest" in readme.lower(), \
        "README must require encrypted-at-rest storage for production"
    assert "reference" in readme.lower(), \
        "README must scope it to the reference implementation"
    # It must point at the actual site, so a reader can find the code.
    assert "actionauth/mcp/hitl.py" in readme, \
        "README note must point at the HITL module that does the caching"
    assert "_MintedCredentialCache.put" in readme, \
        "README note must name the caching method"
