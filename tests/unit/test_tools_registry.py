"""Invariants of the tool registry — properties that must hold for the bridge
to behave correctly."""
from actionauth.tools import SPECS_BY_NAME, TOOL_SPECS


def test_no_duplicate_names():
    names = [s.name for s in TOOL_SPECS]
    assert len(names) == len(set(names))


def test_no_duplicate_cli_names():
    cli_names = [s.cli_name for s in TOOL_SPECS if s.cli_name]
    assert len(cli_names) == len(set(cli_names))


def test_specs_by_name_consistent():
    for s in TOOL_SPECS:
        assert SPECS_BY_NAME[s.name] is s


def test_delete_task_is_hitl_gated():
    """The reference's destructive action must be marked requires_approval=True."""
    spec = SPECS_BY_NAME["delete_task"]
    assert spec.requires_approval is True


def test_delete_task_carries_rar_type():
    """Tier-1 deployments need the RAR `type` string at the spec level."""
    spec = SPECS_BY_NAME["delete_task"]
    assert spec.rar_type == "tasktracker_task_action"


def test_read_tools_are_not_hitl_gated():
    for name in ("list_tasks", "get_task"):
        assert SPECS_BY_NAME[name].requires_approval is False


def test_every_hitl_spec_declares_rar_type():
    """If a tool requires approval, it must declare a RAR type — otherwise the
    Tier-1 deployment cannot construct the consent payload."""
    for s in TOOL_SPECS:
        if s.requires_approval:
            assert s.rar_type is not None, f"{s.name} is HITL-gated but has no rar_type"


def test_schemas_required_fields_present():
    """Every required parameter must be declared in the schema's properties."""
    for s in TOOL_SPECS:
        properties = s.parameters.get("properties", {})
        for required in s.parameters.get("required", []):
            assert required in properties, f"{s.name}: required={required} not in properties"
