"""Shared pytest fixtures."""
import os

import pytest

# Ensure command registration happens before any test imports the registry.
import actionauth.commands  # noqa: F401


@pytest.fixture(autouse=True)
def _bridge_env(monkeypatch, tmp_path):
    """Provide a hermetic env for every test: fresh secrets, fresh token files."""
    monkeypatch.setenv("BRIDGE_A2A_SECRET", "test-a2a-secret")
    monkeypatch.setenv("BRIDGE_APPROVAL_SECRET", "test-approval-secret")
    monkeypatch.setenv("BRIDGE_MCP_SECRET", "test-mcp-secret")
    monkeypatch.setenv("BRIDGE_A2A_TOKEN_FILE", str(tmp_path / "a2a_tokens.json"))
    monkeypatch.setenv("BRIDGE_MCP_TOKEN_FILE", str(tmp_path / "mcp_tokens.json"))
    monkeypatch.setenv("BRIDGE_RS_URL", "http://localhost:9999")
    monkeypatch.setenv("BRIDGE_RS_TOKEN", "test-rs-token")
    # Test isolation for the process-wide default StateBackend (C3).
    # Default-constructed delegation authority / Resource Server instances share the
    # singleton from actionauth.authority.in_memory; without a per-test reset,
    # a signature claimed or a jti consumed by an earlier test leaks
    # into the next test's singleton-backed component and the test sees
    # SignatureReplay / CredentialReplay for a payload it never
    # presented. Resetting before AND after each test makes the
    # singleton inert to inter-test ordering (any test that needs
    # cross-component default-backend sharing builds its own fresh
    # InMemoryStateBackend with a shared dict instead).
    from actionauth.authority.in_memory import reset_default_backend
    reset_default_backend()
    yield
    reset_default_backend()


@pytest.fixture
def fresh_client():
    """A fresh in-memory task store for tests that want a clean slate."""
    from actionauth.core.client import InMemoryTaskStore
    return InMemoryTaskStore()
