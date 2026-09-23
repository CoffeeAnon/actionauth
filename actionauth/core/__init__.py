"""Core dispatch primitives, protocol-surface-agnostic.

  - ``dispatcher.py``: ``Dispatcher`` with the HITL gate. Accepts
                      exactly one of ``authority=`` or ``resource_server=``;
                      routes HITL-gated calls accordingly. Structured
                      outcomes: ``CommandSuccess | CommandError |
                      ApprovalRequired``.
  - ``client.py``:    ``InMemoryTaskStore`` used by the task-tracker
                      example. Production deployments substitute an
                      HTTP client against a real resource server; the
                      dispatcher's contract does not change.
  - ``registry.py``:  ``@command(name=..., hitl=...)`` decorator +
                      ``REGISTRY`` dict (Python's version of Spring
                      auto-discovery).
  - ``output.py``:    lean human-text formatters used by the MCP
                      invoker to render outcomes for LLM consumption.
"""
