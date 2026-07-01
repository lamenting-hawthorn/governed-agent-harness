# ADR 0006: Enforce governance before protected effects

- Status: Accepted
- Date: 2026-07-16
- Decision owners: Project maintainers

## Context

Agent execution engines produce model messages and tool requests, but model
instructions are not a security boundary. Post-hoc observation can explain an
effect after it occurs and advice can influence an engine, yet neither can
prevent an unauthorized file write, network request, message, database change,
secret disclosure, memory promotion, skill installation, or learning import.

The project needs a runtime-neutral invariant that remains true across Pi and
future engines and that users can evaluate without confusing integration depth
with enforcement.

## Decision

Every protected effect must be represented as a versioned, normalized request
and synchronously evaluated by the governance kernel before execution.

The trusted path is:

1. An execution engine or API proposes an effect; it does not execute it.
2. The kernel validates and normalizes the request and trusted actor context.
3. A versioned policy returns an outcome from the canonical JSON Schema policy
   vocabulary defined in `CONTRACTS.md`: `allow`, `deny`, `require_approval`,
   `redact`, or `isolate`.
4. The request and decision are appended to authoritative evidence.
5. Approval, when required, is bound to actor, normalized request hash, policy,
   expiry, nonce, and single consumption.
6. The broker executes only the decision-bound request through the declared
   boundary and records the outcome.

Policy errors, invalid or missing identity, approval mismatch, evidence append
failure, or request mutation deny the effect. An execution engine receives no
ambient filesystem, network, secret, messaging, or mutation capability that
would bypass the broker for a declared Gate or Isolate integration.

Enforcement capabilities are published at four tiers:

- **Observe:** post-hoc event visibility only.
- **Advise:** context or recommendation injection without prevention.
- **Gate:** synchronous decision before each covered effect.
- **Isolate:** Gate plus constrained execution for the covered effect.

Capabilities are declared and tested per effect class. MCP may carry governed
operations but is not, by itself, proof that host-native effects are gated.

Memory promotion, skill installation, policy/configuration mutation, secret
access, provider egress, and learning-artifact import are effects under this
decision even when they are not conventional agent tools.

## Consequences

### Positive

- Policy enforcement is independent of model cooperation.
- Different execution engines can expose honest, testable capability levels.
- Requests, approvals, and outcomes share attributable evidence.
- Tool and memory safety rules use one effect lifecycle.
- Fail-closed behavior is explicit.

### Costs and limitations

- Engines require a real interception boundary for Gate or Isolate support.
- Existing host-native tools that cannot be intercepted remain Observe/Advise.
- The broker and policy service become critical availability dependencies.
- Normalization, approval binding, idempotency, and cancellation require careful
  concurrency design.
- Isolation reduces blast radius but does not guarantee perfect containment.

## Alternatives considered

### Prompt-only policy

Rejected because a model can ignore or be induced to override instructions and
because prompt compliance is not synchronous enforcement.

### Audit after execution

Retained as Observe capability but rejected as the governance boundary because
it cannot prevent harm.

### Engine-specific hooks as the kernel

Rejected because semantics and coverage would drift between engines. Hooks are
adapter mechanisms that must satisfy the common effect contract.

### MCP as the universal enforcement boundary

Rejected because MCP does not automatically intercept tools executed directly
by a host. It remains a useful transport for operations routed through it.

### Approve a whole run or session

Rejected as the default because later arguments, targets, context, or identity
can differ. Policies may issue narrowly scoped, time-bounded capabilities, but
their exact authority and use remain broker-enforced and auditable.

## Verification

The shared conformance suite must attempt direct, nested, alternate-transport,
retry, mutation, replay, cancellation, and concurrency bypasses for every
declared Gate/Isolate effect class. A capability cannot be advertised unless
all declared paths evaluate policy before effect and evidence integrity is
preserved. Known uncovered paths must be labeled Observe or Advise.
