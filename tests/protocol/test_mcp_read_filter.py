"""MCP read-only allowlist + defense-in-depth filter.

These tests defend the contract that the MCP surface in Tier-2 (current)
never exposes HITL-gated tools. Adding a write tool to ``TOOL_SPECS``
without also adding it to ``MCP_V1_ALLOWLIST`` must not leak it onto MCP.
"""
from dataclasses import replace

import pytest

from actionauth import tools as tools_module
from actionauth.tools import SPECS_BY_NAME, TOOL_SPECS, ToolSpec
from actionauth.mcp.tools import MCP_HITL_ALLOWLIST, MCP_V1_ALLOWLIST, mcp_tool_specs


def test_allowlist_contains_only_read_tools():
    for name in MCP_V1_ALLOWLIST:
        spec = SPECS_BY_NAME[name]
        assert not spec.requires_approval, f"{name} is in MCP_V1_ALLOWLIST but requires_approval"
        assert not spec.in_process, f"{name} is in MCP_V1_ALLOWLIST but is in_process"


def test_mcp_tool_specs_excludes_destructive():
    exposed = {s.name for s in mcp_tool_specs()}
    assert "delete_task" not in exposed
    assert "create_task" not in exposed   # not in allowlist
    assert "update_task" not in exposed   # not in allowlist


def test_mcp_tool_specs_includes_reads():
    exposed = {s.name for s in mcp_tool_specs()}
    assert "list_tasks" in exposed
    assert "get_task" in exposed


def test_default_mcp_tool_specs_excludes_hitl_tools():
    """With no HITL gate wired (the default), the surface stays read-only:
    even an explicitly HITL-allowlisted tool like delete_task is not exposed."""
    exposed = {s.name for s in mcp_tool_specs(include_hitl=False)}
    assert "delete_task" not in exposed


def test_hitl_inclusion_exposes_allowlisted_gated_tool():
    """When the gate is wired (include_hitl=True), a gated tool that is
    explicitly in MCP_HITL_ALLOWLIST IS exposed - it's callable through the
    URL-mode elicitation flow. Reads are still exposed."""
    assert "delete_task" in MCP_HITL_ALLOWLIST
    exposed = {s.name for s in mcp_tool_specs(include_hitl=True)}
    assert "delete_task" in exposed
    assert "list_tasks" in exposed and "get_task" in exposed


def test_hitl_inclusion_still_excludes_gated_tool_not_in_hitl_allowlist(monkeypatch):
    """include_hitl exposes ONLY gated tools in MCP_HITL_ALLOWLIST. A gated
    tool absent from that allowlist stays hidden even with include_hitl=True."""
    rogue = ToolSpec(
        name="rogue_destructive",
        description="should not surface on MCP",
        parameters={"type": "object", "properties": {}},
        cli_name="rogue-destructive",
        requires_approval=True,
        rar_type="rogue",
    )
    monkeypatch.setattr(tools_module, "TOOL_SPECS", TOOL_SPECS + [rogue])
    monkeypatch.setattr("actionauth.mcp.tools.TOOL_SPECS", tools_module.TOOL_SPECS)
    # Put it on the READ allowlist but NOT the HITL allowlist.
    monkeypatch.setattr(
        "actionauth.mcp.tools.MCP_V1_ALLOWLIST",
        frozenset(MCP_V1_ALLOWLIST | {"rogue_destructive"}),
    )
    exposed = {s.name for s in mcp_tool_specs(include_hitl=True)}
    assert "rogue_destructive" not in exposed, (
        "a gated tool not in MCP_HITL_ALLOWLIST must never surface, even with "
        "the gate wired and even if it leaks onto the read allowlist"
    )


def test_defense_in_depth_rejects_hitl_tool_added_to_allowlist(monkeypatch):
    """Even if a HITL-gated tool is mistakenly allowlisted, the filter rejects it."""
    rogue = ToolSpec(
        name="rogue_destructive",
        description="should not surface on MCP",
        parameters={"type": "object", "properties": {}},
        cli_name="rogue-destructive",
        requires_approval=True,
        rar_type="rogue",
    )
    monkeypatch.setattr(tools_module, "TOOL_SPECS", TOOL_SPECS + [rogue])
    monkeypatch.setattr(tools_module, "SPECS_BY_NAME", {**SPECS_BY_NAME, rogue.name: rogue})
    monkeypatch.setattr(
        "actionauth.mcp.tools.MCP_V1_ALLOWLIST",
        frozenset(MCP_V1_ALLOWLIST | {"rogue_destructive"}),
    )
    monkeypatch.setattr("actionauth.mcp.tools.TOOL_SPECS", tools_module.TOOL_SPECS)
    exposed = {s.name for s in mcp_tool_specs()}
    assert "rogue_destructive" not in exposed, (
        "MCP surface must not expose HITL-gated tools even if they are mistakenly "
        "added to MCP_V1_ALLOWLIST. The defense-in-depth filter is the contract."
    )
