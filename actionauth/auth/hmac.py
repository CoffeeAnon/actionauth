"""HMAC-bearer-token primitives. Used by both A2A and MCP surfaces."""
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from pathlib import Path

SCOPES = frozenset({"tasks.read", "tasks.write"})


def _token_hash(token: str, secret: str) -> str:
    return hmac.new(secret.encode(), token.encode(), hashlib.sha256).hexdigest()


class TokenStore:
    """File-backed store mapping token-hashes to {scopes, label, issued_at}."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def _load(self) -> dict:
        if self.path.exists():
            return json.loads(self.path.read_text())
        return {}

    def _save(self, data: dict) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.chmod(0o600)
        tmp.replace(self.path)

    def issue(self, scopes: list[str], label: str, secret: str, tenant: str = "local") -> str:
        """Generate a token, store its hash, return the raw token (shown once)."""
        for s in scopes:
            if s not in SCOPES:
                raise ValueError(f"Unknown scope: {s!r}. Valid: {sorted(SCOPES)}")
        token = secrets.token_hex(32)
        h = _token_hash(token, secret)
        data = self._load()
        data[h] = {"scopes": sorted(scopes), "label": label, "tenant": tenant, "issued_at": time.time()}
        self._save(data)
        return token

    def _active_entry(self, token_hash: str) -> dict | None:
        """Return the stored entry IFF it exists and isn't revoked. The single
        place that knows the _revoked filter — all read paths go through this."""
        entry = self._load().get(token_hash)
        return None if entry is None or entry.get("_revoked") else entry

    def list(self) -> list[dict]:
        data = self._load()
        out = []
        for h, v in data.items():
            entry = {"hash_prefix": h[:8], **v}
            entry["revoked"] = bool(entry.pop("_revoked", False))
            out.append(entry)
        return out

    def revoke(self, token: str, secret: str) -> bool:
        h = _token_hash(token, secret)
        data = self._load()
        if h not in data or data[h].get("_revoked"):
            return False
        data[h]["_revoked"] = True
        self._save(data)
        return True

    def has_scope(self, token: str, required_scope: str, secret: str) -> bool:
        h = _token_hash(token, secret)
        entry = self._active_entry(h)
        if entry is None:
            return False
        return required_scope in entry.get("scopes", [])

    def lookup(self, token_hash: str) -> dict | None:
        """Return the stored entry for a token hash, or None if not found (or revoked)."""
        return self._active_entry(token_hash)

    def is_revoked(self, token: str, secret: str) -> bool:
        h = _token_hash(token, secret)
        entry = self._load().get(h)
        return bool(entry and entry.get("_revoked"))


@dataclass(frozen=True)
class CallerIdentity:
    caller_id: str         # 8-char hash prefix — stable, non-reversible
    display_name: str      # label set at issue time; used in HITL prompts and audit log
    scopes: frozenset[str]
    tenant: str = "local"  # placeholder: replaced by JWT iss segment when Keycloak lands


def caller_from_token(token: str, store: "TokenStore", secret: str) -> CallerIdentity:
    h = _token_hash(token, secret)
    entry = store.lookup(h)
    if entry is None:
        raise ValueError("Unknown token")
    return CallerIdentity(h[:8], entry["label"], frozenset(entry["scopes"]), entry.get("tenant", "local"))
