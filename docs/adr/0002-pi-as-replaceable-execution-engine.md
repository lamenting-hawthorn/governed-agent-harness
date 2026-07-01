# ADR 0002: Use Pi Behind a Replaceable ExecutionEngine Boundary

- **Status:** Accepted
- **Date:** 2026-07-16

## Context

A useful agent harness needs model interaction, streaming, tool-call handling,
session lifecycle, cancellation, and provider support. Rebuilding those generic
mechanics would delay the project's differentiating work: enforceable policy,
evidence, governed memory, controlled skills, and learning boundaries.

Pi provides a lightweight TypeScript agent core with relevant hooks and a broad
enough execution surface for the first vertical slice. Making Pi the kernel,
forking it, or leaking Pi event types into public contracts would create a
permanent dependency and make claims of runtime neutrality untrue.

## Decision

Use Pi as the first execution-engine dependency through a dedicated adapter
that implements a versioned `ExecutionEngine` contract.

The boundary must support at least:

- run start, streamed normalized events, completion, cancellation, and timeout;
- proposed tool requests that the kernel can gate before execution;
- context input and governed memory injection;
- engine-specific resume/session references without making them canonical;
- a `CapabilityManifest` declaring observe, advise, gate, isolate, streaming,
  resume, and replay support;
- structured terminal failures and correlation to original engine events.

The governance kernel owns tool registration, policy decisions, approvals,
dispatch, evidence, and memory promotion. The Pi adapter MUST NOT execute an
effect around the governed dispatcher. Kernel and contract packages MUST NOT
import Pi modules or expose Pi-specific types.

## Conformance

Every engine implementation must pass a public conformance suite for each
declared capability. The suite includes attempts to:

- invoke unknown or direct tools;
- mutate arguments after approval;
- emit malformed or duplicate events;
- cancel during policy and execution;
- resume with incompatible state;
- claim isolation when the required boundary is unavailable.

Unsupported capabilities are visible. A policy requiring an unavailable
capability fails closed instead of silently degrading.

## Consequences

### Positive

- The first usable harness benefits from mature execution mechanics.
- Engineering effort focuses on the governance and memory differentiators.
- Another engine can be integrated without replacing kernel contracts.
- Capability differences become testable rather than promotional claims.
- Upstream Pi improvements can be consumed through an ordinary dependency.

### Costs

- The adapter must translate events and session behavior carefully.
- Upstream version changes require compatibility testing and controlled
  upgrades.
- Some Pi features may remain unavailable until they can be represented safely
  by canonical contracts.
- A second implementation or rigorous test double is needed before claiming the
  boundary is proven replaceable.

## Alternatives considered

### Fork Pi

Rejected because it creates a permanent maintenance burden, complicates
upstream updates, and encourages governance logic to leak into the engine.

### Build a new agent loop

Rejected for the initial product because it duplicates non-differentiating
mechanics and expands reliability and provider-compatibility risk.

### Use LangGraph as the kernel

Rejected because a workflow framework should not define public governance,
evidence, or storage contracts. A LangGraph implementation may be added later
as another execution-engine adapter.

### Rely on MCP interception

Rejected as the complete boundary because MCP cannot guarantee governance of
tools executed internally by an arbitrary host. MCP remains an integration
transport for operations the kernel actually controls.

## Upgrade policy

Pi dependency changes are tested against adapter conformance and the complete
governed-effect path before release. Compatible versions are declared and
locked. The project does not expose a newer Pi version as supported until its
adapter and security tests pass.
