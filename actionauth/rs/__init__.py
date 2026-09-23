"""Resource Server primitives.

The Resource Server is the third independent enforcement layer in the
three-layer architecture documented in ``docs/architecture.md``: delegation authority
mints, bridge cannot alter, RS validates and executes. ``JwtResourceServer``
is the executable counterpart that makes that claim demonstrable.

See ``docs/architecture.md`` for the component model
and ``docs/rationale.md`` for the three-tier
graduation.
"""
from actionauth.rs.jwt_resource_server import (
    JwtResourceServer,
    RsError,
    RsOutcome,
    RsRejected,
    RsSuccess,
)

__all__ = [
    "JwtResourceServer",
    "RsError",
    "RsOutcome",
    "RsRejected",
    "RsSuccess",
]
