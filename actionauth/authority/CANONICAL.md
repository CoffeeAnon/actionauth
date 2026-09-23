# Canonical authorization-details format

The HMAC signature authorising a delegation authority to mint a credential is computed over a canonical byte string derived from the structured authorization-details payload. For a signature to verify, the signer and verifier must generate identical bytes.

This document defines the contract for cross-language signer implementations (such as an MCP host in JavaScript or a WebAuthn service in Rust). Any signer conforming to this specification produces bytes accepted by the reference Python verifier.

## Canonical form

A payload is a JSON object with six top-level keys:

| Key | Type | Description |
| --- | --- | --- |
| `cmd` | string | Canonical command name (for example, `"delete-task"`) |
| `args` | object | Exact arguments approved by the user |
| `rar_type` | string | The RAR `authorization_details.type` string |
| `exp` | int | POSIX timestamp in seconds; expires when `now > exp` |
| `approver_id` | string | Opaque approver identity for audit logs |
| `binding_message` | string | Human-readable summary displayed on the consent screen |

In Python, canonical bytes are produced by:

```python
canonical_bytes = json.dumps(
    {
        "cmd": cmd,
        "args": args,
        "rar_type": rar_type,
        "exp": exp,
        "approver_id": approver_id,
        "binding_message": binding_message,
    },
    sort_keys=True,
    separators=(",", ":"),
).encode("utf-8")
```

In other languages, configure the JSON encoder to:

1. Sort object keys lexicographically by Unicode code point at every nesting level.
2. Emit no whitespace between tokens (`{"a":1,"b":2}`).
3. Encode as UTF-8.
4. Escape every non-ASCII character as `\uXXXX` (using UTF-16 surrogate pairs for code points outside the BMP). This matches Python's default `json.dumps(ensure_ascii=True)` behavior. JavaScript's `JSON.stringify` does not do this by default, so JavaScript signers must escape non-ASCII code points before computing the HMAC.

## Type constraints

Cross-language signers must follow these encoding rules:

### `cmd`, `rar_type`, `approver_id`: strings

- Must be UTF-8 encoded.
- Signers should apply Unicode NFC normalization before signing. If a signer emits precomposed `é` and a verifier expects decomposed `é`, the signatures will differ.
- Strings must not contain unescaped control characters (U+0000 through U+001F). Python's `json.dumps` escapes these automatically.

#### Non-ASCII character escaping

Python's `json.dumps` defaults to `ensure_ascii=True`, escaping non-ASCII characters as `\uXXXX`. Non-Python signers must match this behavior to produce identical byte strings.

For example, `approver_id = "alïce@example.com"` (containing `ï`, `U+00EF`):
- Python emits `al\u00efce@example.com`.
- Default JavaScript `JSON.stringify` emits raw UTF-8 bytes `0xc3 0xaf`.

Because differing bytes produce mismatched HMACs, JavaScript signers must escape characters above `U+007F` (using surrogate pairs for characters above `U+FFFF`) before calculating the signature.

Fixture `test_fixture_6_nonascii_approver_id_escapes_to_uXXXX` in `tests/unit/test_canonical_fixtures.py` locks down the byte-exact output for this case.

### `args`: object

- Keys must be strings, sorted lexicographically by Unicode code point.
- Values can be strings, integers, booleans, null, nested objects, or arrays.
- Lists are order-sensitive. Signing `{"tags":["a","b"]}` does not approve `{"tags":["b","a"]}`. Signers must preserve list order between user display and signing.
- Numbers must be integers. Floating-point numbers are rejected during canonicalization.
- Booleans and null must encode as `true`, `false`, and `null`.

### Floats

`canonical_authorization_bytes` raises `TypeError` if any value in `args` is a float. Floats lack a consistent cross-language canonical representation across Python, JavaScript, and Go, and floating-point math can introduce display drift.

Represent fractional values using:
- Fixed-precision integers in minor units (for example, `5099` cents instead of `50.99` dollars).
- Strings parsed with explicit precision (for example, `"50.99"` parsed as a decimal).

Booleans are allowed and serialize as `true` or `false`.

### `exp`: integer

- POSIX timestamp (seconds since 1970-01-01 UTC, integer only).
- Recommended lifetime: 300 seconds (5 minutes).
- The delegation authority enforces an upper bound on requested lifetimes through `max_signed_payload_ttl_seconds` (default 600s). Payloads with expiration timestamps further in the future are rejected at mint time.

### `binding_message`: string

- The human-readable summary displayed to the user on the consent screen.
- Binding this string prevents attacks where a compromised bridge displays one message to the user while asking them to sign a different action. Any difference between what was displayed and what was signed invalidates the signature.
- Signers must sign the exact string shown to the user without reformatting or truncation.

## Signature

HMAC-SHA256 over the canonical bytes, formatted as a 64-character lowercase hex string:

```
signature = hmac_sha256(user_signing_key, canonical_bytes).hex()
```

Verifiers must compare signatures using constant-time comparison functions (such as `hmac.compare_digest` in Python or `crypto.timingSafeEqual` in Node.js).

## Worked example

Signer input:

```python
command = "delete-task"
args = {"task_id": "t-42"}
rar_type = "tasktracker_task_action"
exp = 1779315522
approver_id = "alice@example.com"
binding_message = "Delete the task t-42 (Q2 launch checklist)?"
```

Canonical bytes:

```python
canonical_authorization_bytes(
    "delete-task",
    {"task_id": "t-42"},
    "tasktracker_task_action",
    1779315522,
    "alice@example.com",
    "Delete the task t-42 (Q2 launch checklist)?",
)
# Output:
# b'{"approver_id":"alice@example.com","args":{"task_id":"t-42"},"binding_message":"Delete the task t-42 (Q2 launch checklist)?","cmd":"delete-task","exp":1779315522,"rar_type":"tasktracker_task_action"}'
```

Top-level keys are sorted alphabetically (`approver_id` < `args` < `binding_message` < `cmd` < `exp` < `rar_type`).

Computing the signature with test secret `"demo-user-signing-secret"`:

```python
import hashlib, hmac

canonical = b'{"approver_id":"alice@example.com","args":{"task_id":"t-42"},"binding_message":"Delete the task t-42 (Q2 launch checklist)?","cmd":"delete-task","exp":1779315522,"rar_type":"tasktracker_task_action"}'
sig = hmac.new(
    b"demo-user-signing-secret", canonical, hashlib.sha256
).hexdigest()
# 'e91237e52b6c56d67926fcb6415f24c59e8f42db47ffbe0241c2adcf152bf70a'
```

`tests/unit/test_canonical_fixtures.py` verifies this exact output.

## Validation boundaries

The reference Python implementation generates bytes matching this specification when inputs are valid. It relies on signers to:

- Normalize Unicode strings to NFC form.
- Avoid passing float values in `args`.
- Provide properly formatted `approver_id` strings.

Production systems should add validation guards prior to canonicalization to reject non-conforming inputs.

## Versioning

If the canonical format changes in the future, a version field (`"v": 2`) will be added to top-level keys to prevent signatures from being evaluated under conflicting rules.
