"""MCP streamable-HTTP surface.

Modules:
  - ``server.py``:  ``build_mcp_app(...)`` returns a Starlette ASGI
                    sub-app mounted at ``/mcp`` with bearer-token auth.
                    Implements ``tools/list`` (filtered by the
                    read-only allowlist) and ``tools/call`` (dispatched
                    through the shared ``Dispatcher``).
  - ``invoker.py``: ``InProcessInvoker`` adapter that bridges MCP
                    tool calls to ``Dispatcher.execute()``.
  - ``auth.py``:    bearer-token verification against the shared
                    ``TokenStore`` in ``actionauth.auth.hmac``.
  - ``tools.py``:   defines the v1 read-only allowlist + the
                    defense-in-depth filter that excludes any
                    ``requires_approval=True`` tool from MCP exposure.

Requires the ``[mcp]`` extras: ``pip install -e '.[mcp]'``.
"""
