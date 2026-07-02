# Vision and Scope

## Product thesis

The Governed Agent Harness is a local-first agent runtime in which actions,
memory, skills, and learning are policy-controlled, evidence-backed, and
auditable. It combines a useful interactive agent with a governance kernel
that can make an effect observable, require approval, deny it, or execute it
inside an isolation boundary.

The project is a new, independent system. Governed Agent Architecture (GAA)
and SkillLoop remain independent projects. This repository may adapt their
ideas and exchange versioned artifacts with them, but it does not absorb their
codebases or require either project for its default local experience.

## Why this exists

Most agent harnesses optimize the model loop and add policy, memory, and audit
afterward. That structure makes important controls advisory: a tool can bypass
the policy path, memory can become trusted without evidence, and learning can
modify live behavior without review.

This project makes governance part of the execution path:

```text
request -> identity -> agent engine -> proposed effect -> policy decision
        -> approval or isolation -> execution -> evidence ledger
        -> memory proposal -> governed promotion -> later retrieval
```

Execution engines remain behind a replaceable `ExecutionEngine` contract; the
governance model must not depend on provider-specific events or storage.

## Product principles

1. **Govern effects, not prompts.** Controls run synchronously before an
   external effect and validate the actual arguments at the effect boundary.
2. **Evidence before trust.** Durable memory, evaluation conclusions, and
   learning artifacts retain provenance and an explicit policy decision.
3. **Local first, semantically portable.** A contributor can run the useful
   product without external infrastructure. Hosted deployments preserve the
   same contracts and decisions.
4. **Engines are replaceable.** A provider is a dependency of an adapter, not
   the architectural center of the system.
5. **Capability claims are testable.** Every adapter declares whether it can
   observe, advise, gate, or isolate, and conformance tests verify the claim.
6. **Learning is reviewed input.** Evaluations can propose changes but cannot
   mutate the live runtime automatically.
7. **Secure defaults, explicit escape hatches.** A permissive configuration is
   visible, attributable, and never confused with enforcement.
8. **One operation, multiple transports.** CLI, SDK, daemon, and MCP exposure
   share canonical kernel contracts instead of reimplementing behavior.

## Target users

- **Individual developer:** wants a capable local coding or operations agent
  with persistent memory and clear control over files, shell, and network.
- **Agent application engineer:** embeds governance, memory, and evidence into
  an application while keeping the execution engine replaceable.
- **Platform and security engineer:** defines organizational policy, approval
  paths, isolation levels, retention, and audit export.
- **Evaluator or researcher:** replays runs, tests policies and adapters, and
  exports trace data without granting write access to the live runtime.
- **Enterprise administrator:** operates a tenant-scoped deployment with
  centralized identity, observability, retention, and change controls.

## Primary use cases

### Governed local agent

A developer initializes a project, runs an agent, and sees risky tool requests
allowed, denied, or held for approval before they execute. The run remains
inspectable after restart.

### Evidence-backed long-term memory

The runtime proposes a memory from source evidence. Policy determines whether
it can be promoted. A later session retrieves the approved record with its
scope, provenance, revision, and expiry intact.

### Portable agent governance

An integrator can replace one execution engine with another conforming engine.
Policy,
ledger, identity, memory, and evaluation semantics remain unchanged; only the
capabilities truthfully supported by that engine are enabled.

### Controlled improvement

Completed traces are evaluated locally or exported to SkillLoop. Returned
artifacts are schema-validated, provenance-checked, reviewed, versioned, and
installed explicitly. They never alter a live run by themselves.

### Team or enterprise deployment

The same operation contracts run against hosted storage with authenticated
actors, tenant isolation, centrally managed policy, approval workflows,
retention, and audit export.

## Scope

### In scope for the product

- Interactive and programmatic agent execution through replaceable engines.
- Synchronous policy evaluation for tool calls and other external effects.
- Allow, deny, redact, require-approval, and isolate decisions.
- Append-only run evidence with integrity and provenance metadata.
- Governed semantic, episodic, and procedural memory lifecycles.
- Local embedded storage and hosted Postgres-compatible storage with equivalent
  behavior at the public contract.
- Versioned skills with declared inputs, outputs, permissions, compatibility,
  provenance, and tests.
- Replay and evaluation interfaces, including optional SkillLoop exchange.
- CLI, embeddable SDK, local daemon, and MCP integration where appropriate.
- Adapter and provider conformance suites.
- Diagnostics, migrations, backup/restore, and explicit upgrade behavior.
- Enterprise extension points for identity, authorization, secrets, retention,
  audit export, and observability.

### Out of scope for the initial product

- Forking or reimplementing a provider's general agent loop.
- Merging, modifying, or requiring GAA or SkillLoop.
- Claiming that MCP alone can govern host-native tools.
- Autonomous policy, skill, prompt, or model mutation.
- A general-purpose vector database or knowledge-ingestion platform.
- Training or hosting foundation models.
- A marketplace, billing system, or broad administration UI before the kernel
  and local workflow are stable.
- Feature parity with every agent engine. Capability declarations expose
  differences rather than concealing them.
- Compliance certification. The project can supply controls and evidence, but
  certification requires a deployment-specific program.

## System boundaries

The governance kernel owns identity propagation, policy decisions, approvals,
effect dispatch, evidence, memory promotion, and the public contracts. An
execution engine owns model interaction and generation of proposed tool calls.
Storage providers own persistence, not governance decisions. SkillLoop and
other evaluators consume traces and return proposals through adapters.

Expected architectural detail is documented in `docs/ARCHITECTURE.md`, and the
security trust boundaries are expected in `docs/SECURITY_MODEL.md`.

## Product success

Success is demonstrated by reproducible behavior, not unverified benchmark
claims. The project should measure and publish, with environment and versions:

- Time for a new contributor to complete the documented local quickstart.
- Percentage of supported effect types that traverse a tested policy gate.
- Adapter conformance pass rate by declared capability.
- Replay determinism for policy decisions and recorded inputs.
- Memory records with complete evidence and policy provenance.
- Cross-backend contract conformance for embedded and hosted storage.
- Upgrade, rollback, backup, and restore test success.
- Defect escape rate and time to diagnose using `doctor` and run inspection.
- Evaluation coverage for permission leakage, memory poisoning, prompt
  injection, policy bypass, deletion, contradiction, and tenant isolation.

Targets belong in versioned release criteria once baselines exist. Until then,
documentation reports observations and test results without invented numbers.
