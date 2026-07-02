# ADR 0002: Use a replaceable execution-engine boundary

- **Status:** Accepted
- **Date:** 2026-07-16

## Context

An agent harness needs model interaction, streaming, tool-call handling,
session lifecycle, cancellation, and provider support. Rebuilding those
mechanics inside the governance kernel would couple policy, evidence, and
storage to one execution implementation.

## Decision

Execution engines integrate through a versioned `ExecutionEngine` contract and
a dedicated adapter. The adapter owns provider-specific events, sessions, and
checkpoints. The kernel owns tool registration, policy decisions, approvals,
dispatch, evidence, and memory promotion.

The boundary must support, where declared by the adapter:

- run start, normalized events, completion, cancellation, and timeout;
- proposed tool requests that the kernel can gate before execution;
- context input and governed memory injection;
- engine-specific resume/session references without making them canonical; and
- structured terminal failures correlated to source engine events.

The adapter MUST NOT execute an effect outside the governed dispatcher. Kernel
and contract packages MUST NOT import provider modules or expose provider
specific types.

## Conformance

Every engine implementation must pass a public conformance suite for each
declared capability. The suite attempts direct or unknown tool calls, argument
mutation after approval, malformed or duplicate events, cancellation during
policy and execution, incompatible resume state, and false isolation claims.

Unsupported capabilities are visible. A policy requiring an unavailable
capability fails closed instead of silently degrading.

## Consequences

- Governance remains independent from model and engine implementation details.
- Another engine can be integrated without replacing kernel contracts.
- Capability differences become testable rather than promotional claims.
- Adapters require compatibility testing and a rigorous test double.

## Alternatives considered

### Put the engine inside the kernel

Rejected because it creates permanent coupling and lets provider details leak
into public contracts.

### Build a new agent loop first

Rejected for the initial product because it duplicates non-differentiating
mechanics and expands reliability and provider-compatibility risk.

### Rely on transport interception

Rejected as the complete boundary because a transport cannot guarantee
governance of tools executed directly by a host.
