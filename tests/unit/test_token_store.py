"""Unit tests for actionauth.auth.hmac — the shared TokenStore primitive."""
import pytest

from actionauth.auth.hmac import CallerIdentity, TokenStore, caller_from_token


SECRET = "test-secret"


@pytest.fixture
def store(tmp_path):
    return TokenStore(tmp_path / "tokens.json")


def test_issue_and_authorise_read(store):
    token = store.issue(["tasks.read"], label="alice", secret=SECRET)
    assert store.has_scope(token, "tasks.read", SECRET)
    assert not store.has_scope(token, "tasks.write", SECRET)


def test_issue_unknown_scope_rejected(store):
    with pytest.raises(ValueError, match="Unknown scope"):
        store.issue(["tasks.nope"], label="alice", secret=SECRET)


def test_caller_from_token(store):
    token = store.issue(["tasks.read", "tasks.write"], label="alice", secret=SECRET)
    caller = caller_from_token(token, store, SECRET)
    assert isinstance(caller, CallerIdentity)
    assert caller.display_name == "alice"
    assert "tasks.read" in caller.scopes
    assert "tasks.write" in caller.scopes


def test_revoke(store):
    token = store.issue(["tasks.read"], label="alice", secret=SECRET)
    assert store.has_scope(token, "tasks.read", SECRET)
    assert store.revoke(token, SECRET) is True
    assert not store.has_scope(token, "tasks.read", SECRET)
    # Re-revoke is a no-op.
    assert store.revoke(token, SECRET) is False


def test_unknown_token_has_no_scope(store):
    assert not store.has_scope("definitely-not-issued", "tasks.read", SECRET)


def test_tokens_isolated_by_secret(store):
    token = store.issue(["tasks.read"], label="alice", secret=SECRET)
    assert not store.has_scope(token, "tasks.read", "different-secret")
