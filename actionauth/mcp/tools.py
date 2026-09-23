"""MCP tool registry adapter.

Two explicit allowlists gate what the MCP surface exposes:

  - ``MCP_V1_ALLOWLIST``: read tools, always exposed. Defense-in-depth still
    excludes any spec that is ``requires_approval`` or ``in_process``, so a
    write tool mistakenly added here never leaks onto the read surface.
  - ``MCP_HITL_ALLOWLIST``: HITL-gated tools exposed *only* through the
    URL-mode elicitation flow, and *only* when the server is built with a
    HITL gate (consent store + delegation authority). A gated tool absent from this
    allowlist never surfaces, even with the gate wired.

When no gate is configured the surface stays strictly read-only (the
historical behaviour). Wiring the gate opts the HITL-allowlisted tools in -
this is what makes the single-agent secure-approval path real over MCP,
with no A2A. See the architecture page.
"""
from __future__ import annotations

from actionauth.tools import TOOL_SPECS, ToolSpec

MCP_V1_ALLOWLIST: frozenset[str] = frozenset({
    "list_tasks",
    "get_task",
})

MCP_HITL_ALLOWLIST: frozenset[str] = frozenset({
    "delete_task",
})


def mcp_tool_specs(include_hitl: bool = False) -> list[ToolSpec]:
    """Return the ToolSpecs the MCP surface exposes.

    Read tools (``MCP_V1_ALLOWLIST``, not ``requires_approval``, not
    ``in_process``) are always included. When ``include_hitl`` is True - set
    by the server only when a HITL gate is wired - tools in
    ``MCP_HITL_ALLOWLIST`` are *also* included so they are callable through
    the elicitation flow. A ``requires_approval`` tool that is in neither
    allowlist never surfaces.
    """
    reads = [
        s for s in TOOL_SPECS
        if s.name in MCP_V1_ALLOWLIST
        and not s.requires_approval
        and not s.in_process
    ]
    if not include_hitl:
        return reads
    seen = {s.name for s in reads}
    hitl = [
        s for s in TOOL_SPECS
        if s.name in MCP_HITL_ALLOWLIST
        and not s.in_process
        and s.name not in seen
    ]
    return reads + hitl
