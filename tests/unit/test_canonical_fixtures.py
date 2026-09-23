"""Cross-language stability fixtures for the canonical authorization-details form.

Locks down the byte-level output of ``canonical_authorization_bytes`` and
the HMAC signature for a set of known inputs. If the Python implementation
ever drifts from these fixtures, the test fails immediately — preventing
silent divergence from the spec at ``actionauth/authority/CANONICAL.md``.

These fixtures are the contract a non-Python signer must match. A JS or
Rust signer that produces the same canonical bytes for the same inputs
will produce the same signature, and the Python verifier will accept it.

If you intentionally change the canonical form, update both this file
and ``CANONICAL.md`` in the same commit and bump the version field.
"""
import hashlib
import hmac

from actionauth.authority.in_process import (
    canonical_authorization_bytes,
    sign_authorization_details,
)


USER_SECRET = "demo-user-signing-secret"


# ── Fixture set 1: the minimal delete-task case ─────────────────────────────


_FIX_1_INPUT = dict(
    command="delete-task",
    args={"task_id": "t-42"},
    rar_type="tasktracker_task_action",
    exp=1779315522,
    approver_id="alice@example.com",
    binding_message="Delete the task t-42 (Q2 launch checklist)?",
)
_FIX_1_CANONICAL = (
    b'{"approver_id":"alice@example.com",'
    b'"args":{"task_id":"t-42"},'
    b'"binding_message":"Delete the task t-42 (Q2 launch checklist)?",'
    b'"cmd":"delete-task",'
    b'"exp":1779315522,'
    b'"rar_type":"tasktracker_task_action"}'
)


def test_fixture_1_canonical_bytes():
    actual = canonical_authorization_bytes(**_FIX_1_INPUT)
    assert actual == _FIX_1_CANONICAL


def test_fixture_1_signature():
    sig = hmac.new(USER_SECRET.encode(), _FIX_1_CANONICAL, hashlib.sha256).hexdigest()
    # The signature value below is locked in. If this changes, the canonical
    # form has changed and CANONICAL.md must be updated.
    assert sig == "e91237e52b6c56d67926fcb6415f24c59e8f42db47ffbe0241c2adcf152bf70a"


# ── Fixture set 2: nested dict in args (recursive sort_keys) ────────────────


_FIX_2_INPUT = dict(
    command="update-resource",
    # Deliberately constructed with unsorted keys at every nesting level.
    args={
        "resource_id": "r-1",
        "patch": {"z_last": 1, "a_first": 2, "m_middle": 3},
    },
    rar_type="resource_action",
    exp=1779315522,
    approver_id="bob@example.com",
    binding_message="Update resource r-1",
)
_FIX_2_CANONICAL = (
    b'{"approver_id":"bob@example.com",'
    b'"args":{"patch":{"a_first":2,"m_middle":3,"z_last":1},"resource_id":"r-1"},'
    b'"binding_message":"Update resource r-1",'
    b'"cmd":"update-resource",'
    b'"exp":1779315522,'
    b'"rar_type":"resource_action"}'
)


def test_fixture_2_recursive_key_sort():
    """Nested dicts must have their keys sorted at every level."""
    actual = canonical_authorization_bytes(**_FIX_2_INPUT)
    assert actual == _FIX_2_CANONICAL


# ── Fixture set 3: list values preserve order ──────────────────────────────


_FIX_3_INPUT_AB = dict(
    command="tag-resource",
    args={"id": "r-1", "tags": ["a", "b"]},
    rar_type="tag_action",
    exp=1779315522,
    approver_id="carol@example.com",
    binding_message="Tag resource r-1",
)
_FIX_3_INPUT_BA = dict(
    command="tag-resource",
    args={"id": "r-1", "tags": ["b", "a"]},
    rar_type="tag_action",
    exp=1779315522,
    approver_id="carol@example.com",
    binding_message="Tag resource r-1",
)


def test_fixture_3_list_order_is_significant():
    """The canonical form preserves list order; ["a","b"] != ["b","a"]."""
    ab = canonical_authorization_bytes(**_FIX_3_INPUT_AB)
    ba = canonical_authorization_bytes(**_FIX_3_INPUT_BA)
    assert ab != ba, "list order MUST be significant"


# ── Fixture set 4: sign_authorization_details produces int exp ─────────────


def test_sign_helper_produces_int_exp():
    """Defends against future regressions back to float exp."""
    signed = sign_authorization_details(
        command="delete-task",
        args={"task_id": "t-42"},
        rar_type="tasktracker_task_action",
        approver_id="alice@example.com",
        binding_message="Delete the task t-42?",
        secret=USER_SECRET,
    )
    assert isinstance(signed.exp, int), "exp must be int for cross-language stability"


# ── Fixture set 5: same inputs → identical bytes across calls ──────────────


def test_canonical_is_deterministic():
    """Two calls with the same inputs produce byte-identical output."""
    a = canonical_authorization_bytes(**_FIX_1_INPUT)
    b = canonical_authorization_bytes(**_FIX_1_INPUT)
    assert a == b


# ── Negative fixture: drifted args produce different canonical bytes ──────


def test_arg_drift_changes_canonical_bytes():
    base = canonical_authorization_bytes(**_FIX_1_INPUT)
    drifted_input = {**_FIX_1_INPUT, "args": {"task_id": "t-43"}}
    drifted = canonical_authorization_bytes(**drifted_input)
    assert base != drifted


# ── Fixture set 6: non-ASCII in approver_id (ensure_ascii=True locked in) ──


_FIX_6_INPUT = dict(
    command="delete-task",
    args={"task_id": "t-42"},
    rar_type="tasktracker_task_action",
    exp=1779315522,
    approver_id="alïce@example.com",  # contains U+00EF
    binding_message="Delete the task t-42?",
)
# What the reference produces. A JS signer that emits raw UTF-8 for `ï`
# (default JSON.stringify behaviour) will NOT produce these bytes.
_FIX_6_CANONICAL = (
    b'{"approver_id":"al\\u00efce@example.com",'
    b'"args":{"task_id":"t-42"},'
    b'"binding_message":"Delete the task t-42?",'
    b'"cmd":"delete-task",'
    b'"exp":1779315522,'
    b'"rar_type":"tasktracker_task_action"}'
)


def test_fixture_6_nonascii_approver_id_escapes_to_uXXXX():
    """The canonical form escapes non-ASCII as \\uXXXX (ensure_ascii=True).

    This is load-bearing for cross-language signers: a JS signer that
    emits the raw UTF-8 bytes for `ï` will produce different canonical
    bytes and the signature will mismatch. See CANONICAL.md
    'Non-ASCII strings' section.
    """
    actual = canonical_authorization_bytes(**_FIX_6_INPUT)
    assert actual == _FIX_6_CANONICAL
    # Specifically: the bytes contain the ASCII escape, not the UTF-8 form.
    assert b"\\u00ef" in actual
    assert b"\xc3\xaf" not in actual  # the raw UTF-8 encoding of ï



# ── Fixture set 7: float rejection ───────────────────────────────────────────


def test_canonical_rejects_top_level_float():
    """Floats anywhere in ``args`` raise TypeError before canonicalisation."""
    import pytest
    with pytest.raises(TypeError, match="float values are not permitted"):
        canonical_authorization_bytes(
            command="transfer", args={"amount": 50.99},
            rar_type="payments_transfer", exp=1779315522, approver_id="user@example.com",
            binding_message="Transfer funds",
        )


def test_canonical_rejects_nested_float_in_dict():
    import pytest
    with pytest.raises(TypeError, match=r"args\.payload\.tax"):
        canonical_authorization_bytes(
            command="transfer",
            args={"payload": {"tax": 0.07}},
            rar_type="payments_transfer", exp=1779315522, approver_id="user@example.com",
            binding_message="Transfer funds",
        )


def test_canonical_rejects_nested_float_in_list():
    import pytest
    with pytest.raises(TypeError, match=r"args\.amounts\[1\]"):
        canonical_authorization_bytes(
            command="transfer",
            args={"amounts": [1, 2.5, 3]},
            rar_type="payments_transfer", exp=1779315522, approver_id="user@example.com",
            binding_message="Transfer funds",
        )


def test_canonical_changes_when_binding_message_differs():
    """Binding-message tampering: ``binding_message`` is in the canonical
    bytes, so two payloads identical except for the human-readable
    summary produce different signatures. A compromised bridge that
    renders one message and signs different bytes will fail delegation authority
    verification.
    """
    base = canonical_authorization_bytes(
        command="delete-task", args={"task_id": "t-42"},
        rar_type="tasktracker_task_action", exp=1779315522,
        approver_id="alice@example.com",
        binding_message="Delete the temp file.",
    )
    tampered = canonical_authorization_bytes(
        command="delete-task", args={"task_id": "t-42"},
        rar_type="tasktracker_task_action", exp=1779315522,
        approver_id="alice@example.com",
        binding_message="Delete the production database.",
    )
    assert base != tampered, (
        "binding_message MUST be part of the canonical bytes; "
        "swapping it without changing args must change the signature"
    )


def test_canonical_allows_bool_even_though_int_subclass():
    """``bool`` is a subclass of ``int`` in Python but should pass cleanly."""
    out = canonical_authorization_bytes(
        command="set-flag", args={"enabled": True},
        rar_type="config_set", exp=1779315522, approver_id="user@example.com",
        binding_message="Set flag",
    )
    assert b'"enabled":true' in out
