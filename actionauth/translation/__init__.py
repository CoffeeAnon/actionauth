"""A2A↔MCP protocol translation.

The bridge's *orchestration* contribution (Pattern 1 (see `docs/rationale.md`)):
translate between A2A's task-lifecycle SSE shape and MCP's elicitation
shape so that a human in an MCP host can be the human-in-the-loop for
an action proposed by a remote A2A agent.

This module is intentionally protocol-shape-only — it deals in plain
dataclasses representing the *payloads* that traverse each protocol,
not in the HTTP/SSE transport itself. A production deployment wires
the dataclasses to live A2A `task_status_update` events and MCP
`elicitation/create` JSON-RPC messages via the official SDKs; the
*translation* is what this module captures.

Keeping the translation in pure dataclasses lets the reference
demonstrate the orchestration pattern with no third-party dependencies
and a hermetic test suite. Production code substitutes real SDK
objects for ``A2aAuthRequiredEvent`` and ``McpElicitationRequest``
input/output structures; the translation logic stays unchanged.

See ``actionauth.walkthrough`` for an end-to-end narration of where these
translations slot into the full A2A → bridge → delegation authority → RS → MCP flow.
"""
from actionauth.translation.a2a_mcp import (
    A2aAuthRequiredEvent,
    A2aResumeMessage,
    McpElicitationRequest,
    McpElicitationResponse,
    TranslationError,
    a2a_auth_required_to_mcp_elicitation,
    mcp_elicitation_response_to_a2a_resume,
)

__all__ = [
    "A2aAuthRequiredEvent",
    "A2aResumeMessage",
    "McpElicitationRequest",
    "McpElicitationResponse",
    "TranslationError",
    "a2a_auth_required_to_mcp_elicitation",
    "mcp_elicitation_response_to_a2a_resume",
]
