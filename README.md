# ActionAuth

Human-signed, parameter-bound authorization for agent tool calls.

> [!WARNING]
> **Reference implementation only, not a production template.** This project models parameter-bound delegation, token minting, and protocol conversion between A2A and MCP. To keep the authorization mechanics straightforward to inspect, it leaves out production infrastructure such as consent-server login, CSRF defenses, request throttling, and production-grade storage. It lacks encrypted-at-rest credential storage, a production consent session store, and atomic locking on the flat JSON `TokenStore`. Review [Architectural boundaries and production gaps](#architectural-boundaries-and-production-gaps) and `SECURITY.md` for details.

ActionAuth provides parameter-bound authorization for agent tool calls. A human reviews and cryptographically signs the exact proposed action, a delegation authority mints a single-use warrant restricted to those parameters, and the target resource server rejects any request lacking this warrant. The bridge component translates between [A2A](https://a2a-protocol.org) and [MCP](https://modelcontextprotocol.io), treating both protocols as message carriers.

## Core authorization model

Allowing an LLM to invoke sensitive tools with human approval requires four core properties:

1. **Parameter-bound intent.** The approver's cryptographic signature must bind directly to the command string and argument values. If parameters are unbound, an agent could swap arguments after obtaining human sign-off.
2. **Consent atomicity.** One signed payload mints at most one warrant. If payloads could be reused, an attacker intercepting a signed message could execute duplicate actions throughout the token validity window.
3. **Independent consent surface.** The interface presenting action details to the reviewer must sit outside the trust domain of the orchestrating agent. If co-located, a compromised agent or bridge could display a benign prompt to the reviewer while dispatching harmful parameters for signature.
4. **Destination gating.** The resource server executing the tool must deny every invocation that lacks an authentic, parameter-bound warrant. Omitting this check allows an agent to bypass the approval flow and invoke target interfaces directly.

The reference implementation enforces constraints 1, 2, and 4 directly in code. Constraint 3 requires production architectures to host the consent surface within a separate trust domain, though the bundled local demo runs the consent surface in-process for simplicity.

### Protocol topologies and authority tiers

The security model depends on delegation binding rather than the number of participating agents. Deployments vary by whether the signed approval stays inside one agent's domain or crosses into another:

1. **Single-domain (MCP):** An agent exposes tools through MCP. When an action requires approval, the agent emits a URL elicitation and halts execution until the reviewer signs (`actionauth/mcp/server.py`, `actionauth/mcp/hitl.py`). The entire approval lifecycle stays within that single domain.
2. **Multi-domain (A2A):** When a delegated sub-agent requests a sensitive action, the approval requirement propagates back up to the primary user interface. A2A tasks provide pause and resume mechanics that span domain boundaries, preserve workflow context, and deliver the signed payload back to the initiating agent.

Both topologies represent actions through Rich Authorization Requests (RAR, RFC 9396), where the reviewer signs an `authorization_details` structure that the delegation authority validates before minting a warrant.

The repository provides two implementations of the `DelegationAuthority` interface:

- **Tier 1 (`InProcessAuthority`):** Evaluates HMAC signatures in-process with no third-party services. Protects against prompt injection and argument tampering, but does not defend against agent-process compromise.
- **Tier 2 (`OAuthAuthority` + `JwtResourceServer`):** Separates warrant issuance from resource verification architecturally, with the resource server independently validating tokens and checking parameters. In this reference, both components share a symmetric secret (HS256), so compromising the resource server yields mint capability; production deployments require asymmetric RS256 or ES256 keypairs. Protects against agent-process compromise when user signing keys remain on the client.

---

## Codebase structure and guided reading

To understand how the components interact, review the codebase in sequence:

1. **Core contract (`actionauth/authority/interface.py`):** Inspect the `DelegationAuthority` interface, typed error conditions, and the `SignedAuthorizationDetails` and `MintedCredential` data classes.
2. **Authority implementations (`actionauth/authority/in_process.py` and `actionauth/authority/oauth.py`):** Trace how `canonical_authorization_bytes` computes deterministic byte payloads, then inspect `mint` and `consume`.
3. **Resource server validation (`actionauth/rs/jwt_resource_server.py`):** Examine standalone JWT decoding, expiration boundary enforcement, and parameter matching against incoming arguments.
4. **Dispatch and protocol bridging:** Inspect dispatch enforcement in `actionauth/core/dispatcher.py`, protocol translation in `actionauth/translation/a2a_mcp.py`, elicitation handling in `actionauth/consent/url_mode.py`, and HTTP services in `actionauth/mcp/server.py`.
5. **Simulated workflow (`actionauth/walkthrough.py`):** Run `actionauth walkthrough --tier 2` to observe simulated envelopes traverse the entire flow.

For non-Python signers, see `actionauth/authority/CANONICAL.md` for the exact serialization rules.

### Critical tests

- `tests/e2e/test_three_layer_enforcement.py`: Validates delegation authority pre-mint checks alongside standalone resource server verification.
- `tests/e2e/test_dispatcher_authority_integration.py`: Confirms that forged signatures and replayed payloads are rejected.
- `tests/e2e/test_mcp_elicitation_emission.py`: Drives an MCP server session through gated invocation, URL elicitation, signature approval, and task resumption.

### Directory layout

```
actionauth/
├── authority/             # delegation authority protocol, in-process verifier, and OAuth JWT mint
│   ├── CANONICAL.md     ← cross-language signer specification
│   ├── in_memory.py     ← InMemoryStateBackend and shared replay state
│   └── durable_state.py ← DurableReplayState on SQLite
├── rs/                # JwtResourceServer (third enforcement layer)
├── translation/       # A2A ↔ MCP elicitation translation (dataclasses)
├── consent/           # URL elicitation consent server (Starlette)
│   ├── url_mode.py      ← consent endpoints (render, submit, result)
│   ├── demo_signer.py   ← server-side mock for client-side signing
│   └── durable_consent.py ← DurableConsentStore on SQLite
├── mcp/               # MCP streamable-HTTP endpoints
│   ├── server.py        ← build_mcp_app ASGI factory
│   ├── invoker.py       ← dispatcher adapter for MCP tool calls
│   └── auth.py          ← bearer token verification
├── core/              # Dispatcher, task store, and command registry
├── commands/          # Example task-tracker commands (list, get, create, update, delete)
├── auth/              # TokenStore and CallerIdentity models
├── tools.py           # ToolSpec registry
├── audit.py           # Append-only SQLite audit log
├── cli.py             # CLI command runner
└── walkthrough.py     # End-to-end architecture simulator

tests/
├── unit/              # delegation authority, RS, canonical fixtures, translation, registry
├── e2e/               # Three-layer enforcement, drift, MRTR, and dispatcher tests
└── protocol/          # MCP server, consent server, and tool filter tests
```

To adapt ActionAuth to a different service domain, replace the sample implementations in `actionauth/commands/*.py` and register the resulting tools inside `actionauth/tools.py`.

---

## Verification and test execution

Run the test suite using pytest:

```bash
pytest                       # run all tests (requires [mcp] extra)
pytest tests/unit            # unit tests (delegation authority, RS, canonical fixtures)
pytest tests/e2e             # end-to-end enforcement and workflow tests
pytest tests/protocol        # HTTP server and protocol verification
```

### Architectural guarantees under test

The test suite verifies these properties across the system:

- The `DelegationAuthority` protocol with interchangeable Tier 1 and Tier 2 implementations.
- Cryptographic verification, JWT algorithm pinning, deterministic JSON serialization with multi-language test fixtures, decoupled resource server verification, and drift rejection across layers.
- **Single-use minting.** Delegation authorities record signature digests of approved payloads to reject duplicate minting requests with `SignatureReplay`.
- Protocol translation between A2A events and MCP elicitations in pure data, plus server-side URL elicitation emission and retry handling for restricted tools.
- Dispatcher-level scope enforcement: the dispatcher checks caller bearer scopes against tool `required_scopes` before routing requests to approval.
- Cryptographic binding of user-visible consent messages (`binding_message`) in canonical bytes to prevent display substitution.

### State backends and credential caching

Replay prevention and consent lifecycle state rely on atomic, TTL-bounded backends:

- **`InMemoryStateBackend` (`actionauth/authority/in_memory.py`):** Non-durable store intended for fast single-process unit tests.
- **`DurableReplayState` (`actionauth/authority/durable_state.py`):** SQLite persistence using write-ahead logging (WAL) to survive restarts and coordinate multiple worker processes.

Each authority and resource verifier (`InProcessAuthority`, `OAuthAuthority`, and `JwtResourceServer`) accepts a `StateBackend` instance, defaulting to a shared process-level instance from `get_default_backend()`.

Consent sessions rely on an independent SQLite database through **`DurableConsentStore`** (`actionauth/consent/durable_consent.py`) to coordinate approval state across multiple workers.

**Reference-only storage of cached credentials.** In `actionauth/mcp/hitl.py`, `McpHitlGate.try_resume` caches issued warrants so a retried `tools/call` or a second replica presenting the same approved payload returns the active token instead of re-minting into the delegation authority's `SignatureReplay` guard. This cache stores values via `StateBackend.set_issued` inside the plaintext `command` column alongside Tier 1 bindings, leaving the bearer token **unencrypted** in the SQLite file. This is a deliberate reference-implementation choice: overloading `command` keeps storage to one table. Do not copy this pattern into a production port. Production deployments require dedicated, **encrypted-at-rest** storage or envelope encryption via a key management service (KMS). Refer to the matching warning on `_MintedCredentialCache.put` in `actionauth/mcp/hitl.py`.

---

## Setup and runnable demonstrations

Install the project in a virtual environment:

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .                       # core: stdlib only (CLI, delegation authority, RS, dispatcher, unit tests)
pip install -e '.[mcp]'                # add MCP HTTP server and consent UI
pip install -e '.[dev]'                # add test dependencies
```

Core authorization and verification components require only the Python standard library. The `[mcp]` extra installs Starlette, uvicorn, and the MCP Python SDK.

The CLI provides automated demonstrations:

```bash
actionauth demo all                       # run all scenarios
actionauth demo tier1                     # delete task via Tier 1 InProcessAuthority
actionauth demo tier2                     # delete task via Tier 2 OAuthAuthority
actionauth demo drift --tier 2            # parameter drift after approval is rejected
actionauth demo replay --tier 2           # reused credentials are rejected
actionauth demo key-isolation             # tokens minted by one delegation authority are refused by another
actionauth demo translation               # A2A ↔ MCP translation round-trip
```

The `key-isolation` demo tests cross-delegation authority key separation, not Zero Trust defense under agent compromise. The stronger property is verified in `tests/e2e/test_dispatcher_authority_integration.py::test_tier2_attacker_without_user_secret_cannot_forge_a_new_signature`, which proves that an attacker holding the agent without the user signing secret cannot forge a new signature.

### Interactive walkthrough

To step through the full authorization and dispatch sequence interactively:

```bash
actionauth walkthrough --tier 2           # full trace
actionauth walkthrough --tier 2 --pause   # interactive mode (prompts between steps)
actionauth walkthrough --tier 1           # Tier 1 variant
```

---

## Architectural boundaries and production gaps

### Deliberate non-goals

The reference omits the following infrastructure to keep the core authorization flow easy to follow:

- **Production-grade consent server.** The bundled consent surface omits end-user authentication, CSRF validation, and session-level rate limiting.
- **Durable token persistence.** `TokenStore` uses a flat JSON file without atomic locking.
- **Multi-tenant topology.** The reference models a single deployment containing one delegation authority, one resource server, and one bridge.
- **DPoP sender binding.** Issued warrants travel as bearer tokens without RFC 9449 proof-of-possession constraints.
- **Untrusted MCP host sandboxing.** The reference assumes cooperative MCP hosts controlled by the user.
- **Audit redaction.** Audit logs store argument payloads directly without redacting personally identifiable information (PII).

### Demo implementation shortcuts

Known gaps between the demo implementation and a production deployment:

- **Symmetric signing keys (HS256).** The demo shares symmetric HMAC secrets between the delegation authority and resource server. Production environments should deploy asymmetric RS256 or ES256 keypairs with public keys served via JWKS endpoints.
- **Server-side demo signer.** The helper in `actionauth.consent.demo_signer` signs authorization payloads on the server. Production Tier 2 deployments must collect signatures directly from user client authenticators (such as WebAuthn or Passkeys).
- **In-memory state defaults.** Components default to process-local memory dictionaries. Deployments spanning multiple workers or requiring restart recovery must inject `DurableReplayState` (backed by SQLite) or implement an external backend such as Redis or Postgres behind the `StateBackend` interface.
- **In-process consent UI.** The demo hosts the consent web endpoints directly inside the bridge process. Production architectures must isolate the consent surface in a separate trust domain from the bridge to prevent display substitution.
- **Transport-level scope checks.** MCP bearer tokens verify client identity at the network transport, while `Dispatcher.execute` validates scopes downstream.

---

## Repository license and authorship

ActionAuth is distributed under the Apache-2.0 license. See [LICENSE](LICENSE).

This codebase was built with AI pairing assistance. Architecture, implementation constraints, code reviews, and test assertions were manually directed and verified by the maintainer.
