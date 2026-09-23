# Design rationale

This document explains the reasoning behind the architecture. For component details, sequence diagrams, and failure modes, see `docs/architecture.md`.

## Four necessary and sufficient constraints

Allowing an LLM to invoke sensitive tools with human-in-the-loop (HITL) approval requires four properties. Each addresses a specific failure mode:

1. **Parameter-bound intent.** The human signature covers the exact command and arguments. Without this, an LLM could substitute parameters after receiving approval.
2. **Consent atomicity.** One signed payload mints at most one credential. Without this, a captured payload could be replayed to execute an action multiple times within the signature lifetime.
3. **Independent consent surface.** The service displaying proposed actions to the user sits in a separate trust domain from the agent orchestrating the LLM. Without this separation, a compromised bridge could render one action on screen while submitting different parameters for signing.
4. **Destination gating.** The resource server rejects any request lacking a valid, parameter-bound credential. Without this check, an agent could bypass approval by calling the resource server directly.

The reference code enforces constraints 1, 2, and 4. Constraint 3 requires a consent surface in a separate trust domain from the bridge in production; the bundled demo runs the consent UI in-process for simplicity.

## Cryptographic delegation model

Security rests on parameter-bound token delegation rather than transport protocols:

1. The user signs the exact `(command, args)` payload.
2. The delegation authority verifies the signature and mints a single-use credential containing those arguments (`authorization_details`).
3. The resource server checks the credential against the live request and rejects mismatched arguments or reused tokens.

### Single-domain vs multi-domain paths

What varies between deployments is not the agent count but whether the signed approval stays within one domain or crosses into another's:

- **Single-domain (MCP):** A single MCP server emits a URL elicitation for gated tools and resumes execution once approved (`actionauth/mcp/hitl.py`). The entire approval flow stays within that agent's domain.
- **Multi-domain (A2A):** When an action originates in a sub-agent, the approval request must bubble up to the user's primary interface. A2A tasks provide pause and resume semantics across domain boundaries, preserving context continuity while routing the signed payload back to the originating agent.

## Enforcement layers in Tier 2

Tier 2 implements three independent validation layers:

1. **Delegation authority signature verification:** The delegation authority verifies the HMAC over canonical authorization bytes and records the signature hash to prevent double-minting (`SignatureReplay`).
2. **Bridge pass-through:** The bridge forwards minted credentials to the resource server without modification.
3. **Resource server verification:** The resource server validates JWT signatures, expiration, and argument bindings independently of the delegation authority, tracking consumed token identifiers (`jti`).

This design follows the Rich Authorization Requests (RAR) model from RFC 9396.

## Production consent UI requirements

In the local demo, `actionauth/consent/url_mode.py` runs inside the bridge process. The demo prevents argument tampering using immutable data structures (`ProposedAction` with `frozen=True` and `MappingProxyType`).

In a production deployment with client-side keys (such as WebAuthn), the consent page must be hosted in a separate trust domain from the agent bridge. If the agent bridge serves the consent UI, a compromised bridge could render misleading text in HTML while passing destructive command arguments to the browser's credential API. Hosting the consent page in a separate trust domain ensures the user reviews arguments rendered by a trusted service.

## Three deployment tiers

| Tier | Agent holds write credentials | Gate mechanism | Threat coverage | Infrastructure |
| --- | --- | --- | --- | --- |
| **Tier 0** | Yes | None | None | None |
| **Tier 1** | Yes | In-process HMAC verification | Prompt injection, parameter drift | Single shared secret |
| **Tier 2** | No | External delegation authority mint + RS validation | Agent process compromise, prompt injection, drift | delegation authority, OAuth resource server |

## Interactive authorization for agent workflows

Standard authorization servers evaluate requests against predefined attribute rules (ABAC). This works for predictable service-to-service calls, but fails when an LLM proposes unplanned destructive operations that cannot be anticipated in advance.

When an agent needs to execute an unconfigured or sensitive tool, the bridge pauses execution, renders the exact arguments to the human via MCP elicitation, and submits the resulting signed payload to the delegation authority. The human acts as the dynamic decision-maker, allowing the delegation authority to mint short-lived credentials for arbitrary, contextual actions.

## What this rationale commits the design to

The four constraints above, plus three protocol-level properties:

- **Stateful `context_id` continuity** across MCP tool calls. All tiers.
- **HITL-aware pause/resume.** `auth_required` events translate to MCP elicitations; resume carries the signed payload back. All tiers above Tier 0.
- **Translation-only bridge.** The bridge translates between protocol envelopes but makes no authorization decisions. At Tier 2 this strengthens to delegation-engine: the bridge presents the human's signed approval to a delegation authority and receives a single-use, action-scoped token. The agent holds no persistent destructive credentials between transactions.

See `docs/architecture.md` for the components, flows, and threat model that hold these properties.

## Related work

The MCP elicitation primitive has also been explored in [`draft-embesozzi-oauth-agent-native-authorization-00`](https://datatracker.ietf.org/doc/draft-embesozzi-oauth-agent-native-authorization/) (M. Besozzi, 2026). That draft uses MCP elicitation to deliver user authentication challenges (such as TOTP or WebAuthn identity step-up) through an agent.

By contrast, this reference uses MCP elicitation to authorize specific tool actions with exact parameters (RAR `authorization_details`). Both patterns can compose together: Besozzi's approach verifies user identity, while this reference authorizes specific destructive actions.
