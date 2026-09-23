# Architecture

Companion to `docs/rationale.md`. The rationale explains why the system is designed this way; this document details how components interact, describes message flows, and analyzes the threat model.

The core security model relies on parameter-bound token delegation: a human signs the exact `(command, args)` payload, the delegation authority mints a single-use credential, and the resource server enforces those parameters upon execution. The two walkthroughs below illustrate this pattern across both single-agent MCP flows and multi-agent A2A flows.

## Components

```
                       ┌──────────────────────────────────┐
                       │   Human (approver device)        │
                       │   - Web browser (consent UI)     │
                       │   - Phone (CIBA push)            │
                       └──────────────┬───────────────────┘
                                      │ approves / denies
                                      │ (RAR consent screen)
                                      ▼
                       ┌──────────────────────────────────┐
   ┌──── signed ──────▶│   authority / Delegation Engine  │
   │   RAR payload     │   (OAuth AS, HashiCorp Vault,    │
   │  (HMAC over       │    Entra, IBM Verify, …)         │
   │   authorization_  │                                  │
   │   details)        │   verifies human signature →     │
   │                   │   mints single-use JWT w/        │
   │                   │   authorization_details          │
   │                   │   (RFC 9396), short exp          │
   │                   └──────────────────────────────────┘
   │                                  ▲
   │                                  │ token introspect / JWKS
   │                                  │
   │   ┌──────────────────────────────┴──────────────────────────────┐
   │   │                  Agent service (this reference)             │
   │   │                                                             │
   │   │   ┌────────────────────────┐    ┌────────────────────────┐  │
   │   │   │  A2A interface         │    │  MCP interface         │  │
   │   │   │  (production wiring;   │    │  (`/mcp`)              │  │
   │   │   │   simulated by         │    │  - tools/list          │  │
   │   │   │  walkthrough.py)       │    │  - tools/call          │  │
   │   │   └────────────┬───────────┘    └────────────┬───────────┘  │
   │   │                │                             │              │
   │   │                └───────────┬─────────────────┘              │
   │   │                            ▼                                │
   │   │              ┌──────────────────────────────┐               │
   │   │              │  Tool dispatch + HITL gate   │               │
   │   │              │ (actionauth.core.dispatcher) │               │
   │   │              │  - resolves tool by name     │               │
   │   │              │  - if requires_approval:     │               │
   │   │              │      route to RS (Tier 2)    │               │
   │   │              │      or authority (Tier 1)   │               │
   │   │              └──────────────────────────────┘               │
   │   │                            │                                │
   │   └────────────────────────────┼────────────────────────────────┘
   │                                ▼
   │              ┌──────────────────────────────┐
   │              │  Resource server             │
   │              │  (actionauth.rs.             │
   │              │   JwtResourceServer)         │
   │              │  - validates Bearer token    │
   │              │  - verifies                  │
   │              │    authorization_details     │
   │              │    matches request           │
   │              │  - executes (or rejects on   │
   │              │    drift / replay)           │
   └──────────────┴──────────────────────────────┘
```

## Delegation authority contract

Both `InProcessAuthority` (Tier 1) and `OAuthAuthority` (Tier 2) implement a shared `DelegationAuthority` protocol:

- **`mint(signed_authorization_details) -> MintedCredential`**: Verifies the human signature, then mints a single-use credential bound to the approved arguments. Both implementations enforce a maximum TTL via `max_signed_payload_ttl_seconds` (default 600s); requests with expiration timestamps beyond this window are rejected as `PayloadDriftAtMint`.
- **`consume(credential, command, args) -> MintedCredential`**: Validates the credential against the live request at execution time and marks the token consumed. Replays, argument drift, expiration, and invalid signatures raise typed exceptions.

### Structural parameter immutability

Between emitting an elicitation and receiving a signature, the bridge preserves proposed actions in an immutable dataclass (`ProposedAction` in `actionauth.consent.url_mode`, configured with `frozen=True` and `types.MappingProxyType` over copied arguments). This prevents in-place mutation or reassignment, ensuring the parameters signed by the user cannot change before submission to the delegation authority.

The dispatcher calls `consume` directly (or forwards the token to the resource server for independent verification in Tier 2).

## Three independent enforcement layers (Tier 2)

Tier 2 distributes validation across three isolated layers (verified by `tests/e2e/test_three_layer_enforcement.py`):

1. **Delegation authority verifies user signatures before minting** (`OAuthAuthority.mint`). It rejects invalid signatures with `SignatureMismatch`, expired payloads with `CredentialExpired`, and excessive TTLs with `PayloadDriftAtMint`.
2. **Bridge passes credentials without modification** to the resource server (`Dispatcher._execute_via_rs`). The dispatcher implementation is intentionally a minimal pass-through.
3. **Resource server validates tokens independently** (`JwtResourceServer.execute`). It uses its own verification keys, validates `iss`, `aud`, and `exp` claims, maintains its own consumed token state, and confirms that `authorization_details` match the active command arguments.

The bridge relays requests between layers without verifying tokens itself.

### Layer trust boundaries

Layers 2 and 3 operate independently: a failure in one does not compromise the other. However, Layer 1 is the single trust root for user signature verification. Because the resource server validates the minted JWT rather than the human HMAC signature directly, a bug in the delegation authority that mints without verifying the signature will go unnoticed downstream. Layers 2 and 3 protect execution after token creation; Layer 1 determines whether token creation should occur.

## Walkthroughs

### 1. `delete_task` via A2A (multi-agent target architecture)

```
Client                       Agent service                 authority                 RS
  │                                  │                       │                    │
  │── POST /a2a (delete) ───────────▶│                       │                    │
  │                                  │ validate t-base       │                    │
  │                                  │  (tasks.read only)    │                    │
  │                                  │ dispatch sees         │                    │
  │                                  │ requires_approval     │                    │
  │◀── SSE: auth_required            │                       │                    │
  │    parts=[DataPart {             │                       │                    │
  │      authorization_details,      │                       │                    │
  │      binding_message }]          │                       │                    │
  │                                  │                       │                    │
  │ (human approves; client signs    │                       │                    │
  │  HMAC over canonical bytes)      │                       │                    │
  │                                  │                       │                    │
  │── POST /a2a (resume with         │                       │                    │
  │   approved + signature) ────────▶│                       │                    │
  │                                  │── present signed     ▶│                    │
  │                                  │   RAR for verify     │                    │
  │                                  │   + mint              │                    │
  │                                  │◀── single-use JWT ────│                    │
  │                                  │                       │                    │
  │                                  │── DELETE /tasks/X ───────────────────────▶│
  │                                  │   Bearer t-delete-X   │                    │
  │                                  │                       │                    │ validate token,
  │                                  │                       │                    │ match auth_details
  │                                  │                       │                    │ to live request,
  │                                  │                       │                    │ mark consumed,
  │                                  │                       │                    │ delete
  │                                  │◀──────── 204 ─────────────────────────────│
  │◀── SSE: completed                │                       │                    │
```

### 2. `delete_task` via MCP (single-agent reference implementation)

This flow runs directly in the reference codebase. An MCP agent emits a URL elicitation for approval and resumes execution on retry without A2A (`tests/e2e/test_mcp_elicitation_emission.py`).

```
MCP host (LLM)              Agent service                    authority                RS
  │                               │                            │                   │
  │── tools/call delete_task ────▶│                            │                   │
  │                               │ dispatch sees              │                   │
  │                               │ requires_approval          │                   │
  │                               │ → build authorization_     │                   │
  │                               │   details                  │                   │
  │◀── elicitation/create        │                            │                   │
  │    {mode:"url",               │                            │                   │
  │     url: actionauth/consent/…}│                            │                   │
  │                               │                            │                   │
  │ (human visits URL, reviews    │                            │                   │
  │  action, signs)               │                            │                   │
  │                               │                            │                   │
  │── elicitation/response       │                            │                   │
  │    accept + signed payload ──▶│                            │                   │
  │                               │── present signed RAR ─────▶│                   │
  │                               │◀──── minted JWT ───────────│                   │
  │                               │                            │                   │
  │                               │── DELETE /tasks/X ────────────────────────────▶│
  │                               │◀──── 204 ─────────────────────────────────────│
  │◀── tools/call result         │                            │                   │
```

Both MCP and A2A follow the same verification steps; only the transport message format differs.

## State and persistence

### Context continuity

The agent service tracks conversations by `context_id`. In MCP flows, the session identifier in `elicitation_id` maps back to the active conversation (`elicitation_id = "el:<context_id>:<task_id>:<b64url(tag)>"`). An HMAC tag over `(context_id, task_id)` keyed with the bridge's process-local secret prevents forging valid IDs. The bridge verifies this tag and recovers `context_id` when handling elicitation responses in `actionauth.translation.mcp_elicitation_response_to_a2a_resume`.

### Token lifecycle

- **Base token**: Long-lived per-session token issued at client setup, carrying read scope (`tasks.read`). Validated on every incoming request.
- **Action-scoped token**: Single-use, short-lived credential (default 5 minutes), bound to specific tool arguments. Minted upon human approval and validated during tool execution.

**Restart behavior:** The default in-memory state backend tracks consumed tokens in memory. If the process restarts within a token's lifetime, records are lost. Production deployments should configure persistent storage using `DurableReplayState` (backed by SQLite) or implement an external backend such as Redis or Postgres behind the `StateBackend` interface.

### Audit logging

Every dispatch event writes a record to `AuditSink` in SQLite. The demo emits `tool_call` entries; the schema also supports `approval_granted`, `approval_rejected`, and `error` event types.

## Failure modes

| Mode | Behavior |
| --- | --- |
| Approval denied | User denies consent; resume runs with `approved=False`; dispatcher returns `ApprovalRequired(reason="decline")`. |
| Approval timeout | Consent session expires before approval; resume runs with `approved=False`. |
| Parameter mismatch | Arguments differ from the approved payload; dispatcher returns `ApprovalRequired(reason="CredentialDrift")`. |
| Process restart during pause | In-memory pending gates are cleared; resume requests fail signature verification (Tier 1) or replay checks (Tier 2). |
| Token replay | Re-executing a consumed token raises `CredentialReplay`. Presenting the same signed payload twice raises `SignatureReplay` at mint. |

## Threat model

| Threat | Mitigation |
| --- | --- |
| **Prompt-injected agent** attempts destructive action. | The agent holds only read permissions. Destructive commands trigger an approval event that requires user confirmation; the LLM cannot fabricate the necessary signature. |
| **Compromised agent process.** | In production, agents hold only base read credentials. Action tokens exist briefly between minting and consumption. Moving user signing client-side (WebAuthn) prevents a compromised agent from generating valid signatures. |
| **Parameter drift after approval.** | Three independent checks prevent drift: (1) proposed actions are stored in frozen dataclasses, (2) the delegation authority verifies the HMAC over canonical arguments before minting, and (3) the resource server matches token claims against incoming parameters. |
| **Token replay across requests.** | Resource servers track consumed `jti` identifiers. Delegation authorities track signature hashes at mint time (`SignatureReplay`), preventing repeated minting from one approval. |
| **Bridge compromise.** | In production, the bridge cannot mint tokens unilaterally because signing keys remain on the user device. |
| **Delegation authority compromise.** | Out of scope; the delegation authority is the trust root. Standard key protection and access controls apply. |
| **User signing key compromise.** | Out of scope; equivalent to a compromised user account. Mitigated by hardware-backed keys (WebAuthn / Secure Enclave). |
| **Denied action retried without approval.** | Retrying a denied command generates a new approval request; prior denials are never cached as approvals. |
| **Untrusted MCP host.** | The `elicitation_id` is an HMAC-tagged carrier (`el:<context_id>:<task_id>:<tag>`), so a host without the tag secret cannot fabricate IDs that the bridge will accept. A multi-replica or shared-host deployment where the tag secret cannot be confined must replace the carrier with a signed token. See `actionauth.translation.a2a_mcp`. |

## Intentional demo omissions

- **OAuth authorization server**: `OAuthAuthority` is an in-process HS256 mock. Production setups should use standard OAuth authorization servers (such as Keycloak, Auth0, or Hydra).
- **Asymmetric cryptographic keys**: The demo uses symmetric HMAC secrets between delegation authority and resource server. Production requires RS256/ES256 with JWKS endpoints.
- **Client-side signing**: `actionauth.consent.demo_signer` simulates client signatures on the server. Production should use WebAuthn or Passkeys directly on the user device.
- **Federation**: The reference runs a single delegation authority, single resource server, and single bridge instance.
- **DPoP tokens**: Tokens are bearer-based rather than sender-constrained with RFC 9449.
