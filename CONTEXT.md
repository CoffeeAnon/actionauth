# ActionAuth

Parameter-bound, human-in-the-loop delegation for agent tool calls. A human signs the exact action an agent proposes, a delegation authority mints a single-use warrant for those exact bytes, and the resource server honours nothing else.

## Language

**ActionAuth** (the project):
The name of this project and of its reference implementation: authorization bound to one action.
_Avoid_: A2A-MCP bridge, the bridge (as a project name), Warrant (as the project name; it is the credential), delegation engine (as a name; fine as a description)

**Warrant** (the credential):
The single-use, parameter-bound, time-limited credential a delegation authority mints after verifying a human's signature over one exact action.
_Avoid_: approval token, single-use credential, capability

**Token**:
The wire encoding that carries a warrant, such as an HMAC string or a JWT. A token is how a warrant travels, not the concept itself.
_Avoid_: token as the name of the concept

**Delegation authority**:
The party that verifies the human's signature over an action and mints the warrant (`DelegationAuthority` in code). HashiCorp Vault is one possible backing service and is always named in full.
_Avoid_: Vault (the old component name), Vault meaning the HashiCorp product

**Bridge**:
The component that translates between the A2A and MCP carriers. A component name only, never the project.
_Avoid_: the bridge meaning the project or the whole system

**Consent surface**:
The service that shows the human the proposed action and collects their signature. It lives in a separate trust domain from the agent.
_Avoid_: consent page (the page is one part of the surface), approval UI

**Resource server**:
The service that performs the action and refuses any request not carrying a valid warrant for exactly that action.
_Avoid_: backend, target, tool server

**Reference**:
This repository: the public implementation of ActionAuth that demonstrates the flow and deliberately omits production infrastructure.
_Avoid_: the library, the framework

**Implementation**:
A deployable composition of the reference for one estate, in its own repository, depending on the reference as a pinned package.
_Avoid_: fork, the production version
