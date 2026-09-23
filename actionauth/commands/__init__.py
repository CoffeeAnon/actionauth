"""Task-tracker example commands.

Five commands matching the example domain:

  - ``list_tasks``   (read-only)
  - ``get_task``     (read-only)
  - ``create_task``  (write, not HITL-gated in the reference)
  - ``update_task``  (write, not HITL-gated in the reference)
  - ``delete_task``  (**destructive — HITL-gated**, ``rar_type="tasktracker_task_action"``)

Importing this package side-effect-registers every command into
``actionauth.core.registry.REGISTRY`` via the ``@command`` decorator
defined in ``actionauth.core.registry``. The CLI, tests, and walkthrough
each ``import actionauth.commands`` once at startup so the dispatcher can
look up commands by name.

Replace this directory with your own domain commands when adapting
the reference: each file declares one ``@command`` class implementing
``BaseCommand.execute(client, **kwargs)``. The HITL gate is engaged
by setting ``hitl=True`` on the decorator and a matching ``rar_type``
on the corresponding ``ToolSpec`` in ``actionauth/tools.py``.
"""
from actionauth.commands import list_tasks, get_task, create_task, update_task, delete_task  # noqa: F401
