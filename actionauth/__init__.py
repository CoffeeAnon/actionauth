"""ActionAuth: a parameter-bound authorization reference for A2A and MCP.

Two patterns demonstrated:

  - **Pattern 1 (orchestration)** — ``actionauth.translation``: translate
    between A2A ``auth_required`` SSE events and MCP elicitation
    requests, preserving ``context_id`` continuity, ``authorization_details``
    byte-identity, and URL-mode-for-sensitive-consent.

  - **Pattern 2 (cryptographic delegation)** — ``actionauth.authority``: every
    destructive action is approved by a human signing the specific
    RAR-shaped ``authorization_details`` payload. The signature drives
    the delegation authority to mint a single-use, action-scoped credential;
    ``actionauth.rs`` validates the credential against the live request,
    independently of the delegation authority. Three enforcement layers.

Read ``README.md`` for the reading order, the CLI quickstart, and
the documented limitations of this reference. See `docs/rationale.md` and `docs/architecture.md` for
the design rationale and the architectural target.
"""
