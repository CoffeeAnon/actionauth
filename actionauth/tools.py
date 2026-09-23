"""Tool registry: single source of truth for agent tool metadata.

Each ToolSpec captures:
- `name`: the name the LLM sees in function-calling (snake_case)
- `description`: the LLM-facing description (used by `tools/list` and prompt context)
- `parameters`: JSON Schema exposed to the LLM
- `cli_name`: corresponding CLI subcommand (kebab-case); None for in-process tools
- `requires_approval`: True if the tool hits the HITL gate
- `required_scopes`: scopes the caller's bearer must carry to execute this tool.
  Enforced by ``Dispatcher.execute`` *before* HITL routing. The HITL gate is an
  orthogonal concern: scope says "is this caller allowed to attempt this tool at
  all"; HITL says "for this particular destructive attempt, did a human approve
  this exact action shape." A reader who skips scope enforcement ends up with
  "least privilege only for destructive things" — see ``SECURITY.md``
  for the rationale.
- `in_process`: True if the tool is dispatched inside the graph (not via subprocess)
- `rar_type`: RFC 9396 `authorization_details.type` string used by the Tier-1 OAuth
  deployment to construct the consent payload. Only meaningful when
  `requires_approval=True`.

The reference example domain is a task-tracker:
  - list_tasks, get_task: read tools, no approval
  - create_task, update_task: writes, no HITL in the v1 reference (deployments
    can add a gate by setting requires_approval=True and a rar_type)
  - delete_task: destructive, HITL-gated
"""
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]
    cli_name: str | None = None
    requires_approval: bool = False
    required_scopes: tuple[str, ...] = ()
    in_process: bool = False
    rar_type: str | None = None


_TASK_ID = {"task_id": {"type": "string", "description": "Task identifier."}}


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec(
        name="list_tasks",
        cli_name="list-tasks",
        description="List all tasks with their IDs, titles, and current status.",
        parameters={"type": "object", "properties": {}, "required": []},
        required_scopes=("tasks.read",),
    ),
    ToolSpec(
        name="get_task",
        cli_name="get-task",
        description="Read a single task by ID, returning all fields.",
        parameters={
            "type": "object",
            "properties": dict(_TASK_ID),
            "required": ["task_id"],
        },
        required_scopes=("tasks.read",),
    ),
    ToolSpec(
        name="create_task",
        cli_name="create-task",
        description="Create a new task with the given title and optional description.",
        parameters={
            "type": "object",
            "properties": {
                "title": {"type": "string", "description": "Task title."},
                "description": {"type": "string", "description": "Optional longer description."},
            },
            "required": ["title"],
        },
        required_scopes=("tasks.write",),
    ),
    ToolSpec(
        name="update_task",
        cli_name="update-task",
        description="Update one or more fields on an existing task.",
        parameters={
            "type": "object",
            "properties": {
                **_TASK_ID,
                "title": {"type": "string", "description": "New title."},
                "description": {"type": "string", "description": "New description."},
                "status": {
                    "type": "string",
                    "enum": ["open", "in_progress", "done"],
                    "description": "New status.",
                },
            },
            "required": ["task_id"],
        },
        required_scopes=("tasks.write",),
    ),
    ToolSpec(
        name="delete_task",
        cli_name="delete-task",
        requires_approval=True,
        rar_type="tasktracker_task_action",
        required_scopes=("tasks.write",),
        description=(
            "Delete a task by ID. Destructive; requires human approval before "
            "execution. The approval is bound to this exact task_id; any "
            "attempt to delete a different task requires a new approval."
        ),
        parameters={
            "type": "object",
            "properties": dict(_TASK_ID),
            "required": ["task_id"],
        },
    ),
]


SPECS_BY_NAME: dict[str, ToolSpec] = {s.name: s for s in TOOL_SPECS}
SPECS_BY_CLI_NAME: dict[str, ToolSpec] = {s.cli_name: s for s in TOOL_SPECS if s.cli_name}
