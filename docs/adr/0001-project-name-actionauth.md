---
status: accepted
date: 2026-09-06
updated: 2026-09-22
---

# The project is named ActionAuth

"A2A-MCP bridge" described the first carrier, not the thing itself: the security core is a parameter-bound delegation engine in which a human signs the exact `(command, args)`, a delegation authority mints a single-use credential, and the resource server gates on it. The project is renamed **ActionAuth**: authorization for one specific action, with named parameters, issued after human review. "Warrant" was chosen on 2026-09-06; on 2026-09-17 Dan reverted to the original ActionAuth decision. The rename landed on 2026-09-22: repositories, package, console script and README.

## Considered options

- **Warrant.** Chosen on 2026-09-06 and superseded on 2026-09-17: Dan kept the original ActionAuth name rather than force a second rename through the public surfaces. `warrant` stays the glossary term for the minted credential.
- **Other single words.** `marque` (letter of marque: the sovereign delegating one bounded act to a privateer) was the strongest alternative and lost only on familiarity. `mandate` also reads as "requirement". `firman`, `placet`, `rescript` were free everywhere but need the tagline to do all the work.
- **Coined words.** `consentry`, `parabound`, `sigmint` were free on PyPI and GitHub. Rejected because a real word with a clear tagline beats a coinage nobody can guess.
- **Descriptive compounds.** `signed-intent`, `hitl-delegation`, `boundwarrant`. Nothing to explain, nothing to remember.

## Consequences

- Repository slug: `CoffeeAnon/actionauth` for the reference. A deployment-specific implementation lives in its own repository. "Reference implementation" lives in the description and README warning, not the slug.
- The `bridge` Python package and `bridge` console script become `actionauth`. "Bridge" survives only as the name of the A2A/MCP translation component.
- The implementation pins the reference as a git dependency; a PyPI distribution name is chosen only if an external consumer ever needs one.
- "Warrant" is the glossary term for the minted credential; "token" is reserved for the wire encoding. The `Vault` component became the delegation authority in code.
