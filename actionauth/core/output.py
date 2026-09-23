"""Lean human-readable formatters for tool outcomes.

Used by the MCP invoker to render `CommandSuccess.items` / `CommandError`
payloads as text the host LLM can consume directly. Format optimised for
LLM-consumption token-economy (no XML wrapper boilerplate, meta block
suppressed because it tells the LLM nothing it didn't already know).
"""


def to_human(command: str, items: list[dict], meta: dict) -> str:
    """Format a `CommandSuccess` as `key=value, key=value` lines, one per item."""
    lines = [", ".join(f"{k}={v}" for k, v in item.items()) for item in items]
    if not lines:
        lines.append("(no results)")
    return "\n".join(lines)


def error_human(
    command: str, status: int | str, message: str, context: dict | None = None,
) -> str:
    """Format a `CommandError` as a human-readable error block."""
    lines = [f"Error in {command} ({status}): {message}"]
    for key, value in (context or {}).items():
        lines.append(f"  {key}: {value}")
    return "\n".join(lines)
