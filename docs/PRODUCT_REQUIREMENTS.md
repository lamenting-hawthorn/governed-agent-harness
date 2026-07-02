# Product Requirements

## Status and interpretation

This document defines the product-level requirements for the new Governed
Agent Harness. Requirement identifiers are stable references for architecture,
implementation, tests, and release gates. A requirement is not considered met
until an automated test or documented verification demonstrates it.

Normative words **MUST**, **SHOULD**, and **MAY** follow RFC 2119 usage.

## Personas and outcomes

| Persona | Required outcome |
| --- | --- |
| Local developer | Install, initialize, run, approve, inspect, and resume an agent without external services. |
| Integrator | Embed the kernel or connect an engine/provider through versioned contracts and conformance tests. |
| Security engineer | Express enforceable policy and prove that effects cannot bypass the decision point. |
| Evaluator | Replay recorded runs and exchange traces without permission to mutate the runtime. |
| Enterprise operator | Operate authenticated, tenant-scoped, observable, recoverable hosted infrastructure. |

## Functional requirements

### Initialization and configuration

- **FR-001:** The CLI MUST initialize a project with a versioned configuration,
  an explicit data location, a policy profile, and no embedded secrets.
- **FR-002:** Local initialization MUST work without an external database,
  daemon, identity provider, or SkillLoop installation.
- **FR-003:** Configuration MUST have a documented precedence order across
  defaults, files, environment variables, and explicit CLI arguments.
- **FR-004:** Configuration parsing MUST reject unknown security-sensitive
  fields and invalid combinations rather than silently downgrading enforcement.
- **FR-005:** `doctor` MUST diagnose configuration, storage, migrations,
  engine/provider compatibility, policy loading, and required isolation tools.

### Execution engines

- **FR-010:** The kernel MUST invoke an engine only through the versioned
  `ExecutionEngine` contract.
- **FR-011:** Every execution-engine implementation MUST live in a dedicated
  adapter package; kernel packages MUST NOT import provider modules.
- **FR-012:** Each engine MUST publish a `CapabilityManifest` declaring its
  support for observe, advise, gate, isolate, streaming, resume, and replay.
- **FR-013:** An engine MUST pass conformance tests for every capability it
  declares. Unsupported capabilities MUST fail closed when required by policy.
- **FR-014:** Engine events MUST normalize into canonical `AgentEvent` records
  without losing the provider's original event reference.
- **FR-015:** Cancellation, timeout, model failure, and malformed tool requests
  MUST produce explicit terminal events.

### Tool and effect governance

- **FR-020:** Every registered effectful tool MUST submit a validated
  `ToolRequest` to synchronous policy evaluation before dispatch.
- **FR-021:** Policy decisions MUST include decision, reason, policy version,
  actor, requested effects, timestamp, and a correlation identifier.
- **FR-022:** The decision set MUST support allow, deny, redact/transform,
  require approval, and require isolation.
- **FR-023:** Arguments MUST be validated again at the execution sink after any
  policy transformation.
- **FR-024:** Approval requests MUST bind to an immutable digest of the exact
  tool, arguments, actor, scope, and policy decision. Changed requests require
  new approval.
- **FR-025:** A denied, expired, cancelled, or malformed request MUST NOT
  execute and MUST generate evidence.
- **FR-026:** The dispatcher MUST reject direct engine attempts to execute an
  unregistered or ungoverned effect.
- **FR-027:** Filesystem, shell, network, external messaging, database mutation,
  credential access, memory writes, skill installation, and runtime policy
  changes MUST be classifiable as effects.
- **FR-028:** If synchronous policy evaluation is unavailable, times out, or
  fails, every effectful request MUST fail closed. This behavior MUST NOT be
  configurable. Only non-effectful processing and ancillary telemetry MAY
  degrade without policy evaluation.

### Evidence and run inspection

- **FR-030:** Each run MUST create append-only evidence envelopes for inputs,
  normalized events, decisions, approvals, effects, outputs, and termination.
- **FR-031:** Evidence MUST include source and content identity, actor and tenant
  scope, timestamps, schema version, and integrity metadata.
- **FR-032:** Sensitive fields MUST be redacted or encrypted according to policy
  before evidence leaves its permitted trust boundary.
- **FR-033:** A user MUST be able to inspect a run and follow correlation links
  from request through policy decision to effect and result.
- **FR-034:** Export MUST preserve provenance and mark omissions or redactions.
- **FR-035:** Retention, deletion, and legal-hold operations MUST be explicit,
  authorized, and evidenced.

### Memory and knowledge

- **FR-040:** Raw conversation or tool output MUST NOT become committed memory
  merely because it appeared in a run.
- **FR-041:** A `MemoryProposal` MUST reference source evidence or be rejected.
- **FR-042:** Memory promotion MUST record an explicit policy decision and the
  policy version used.
- **FR-043:** Committed memory MUST retain type, scope, authority, confidence,
  provenance, validity, retention, revision, and supersession metadata.
- **FR-044:** Retrieval MUST enforce actor and tenant scope before ranking.
- **FR-045:** Corrections MUST create an auditable revision or supersession;
  destructive overwrite MUST NOT erase prior evidence.
- **FR-046:** Expired, deleted, quarantined, or superseded memory MUST not be
  injected as active context unless an authorized audit operation requests it.
- **FR-047:** Embedded-local and hosted providers MUST pass the same memory
  lifecycle and retrieval authorization conformance suite.

### Skills

- **FR-050:** A skill package MUST include semantic version, integrity identity,
  input/output schema, requested permissions, compatibility, and provenance.
- **FR-051:** Installing or upgrading a skill MUST NOT grant permissions without
  policy evaluation and, where required, approval.
- **FR-052:** Skill resolution MUST be deterministic for a given lockfile and
  MUST surface incompatible engine or contract versions before execution.
- **FR-053:** Skill installation, update, disablement, rollback, and removal
  MUST be evidenced.
- **FR-054:** Skills SHOULD include deterministic behavior tests and routing
  evaluations that can run without privileged production access.

### Evaluation and controlled learning

- **FR-060:** The runtime MUST expose completed traces through a versioned,
  redaction-aware evaluation interface.
- **FR-061:** Replay MUST identify which inputs are recorded and which external
  effects are simulated, blocked, or re-executed.
- **FR-062:** SkillLoop support MUST be optional and implemented through an
  adapter; the core local path MUST not depend on SkillLoop.
- **FR-063:** Returned evaluation, memory, skill, or policy proposals MUST pass
  schema, provenance, compatibility, and policy validation before installation.
- **FR-064:** No evaluator or learning system MAY mutate the live runtime merely
  by returning an artifact.
- **FR-065:** Installation of a learning artifact MUST be explicit, versioned,
  evidenced, reviewable, and reversible.

### Interfaces

- **FR-070:** CLI, SDK, daemon, and MCP interfaces MUST call canonical kernel
  operations and preserve the same authorization and policy semantics.
- **FR-071:** MCP MUST be documented as an integration transport, not proof that
  tools executed internally by an arbitrary host are governed.
- **FR-072:** Public operations and persisted schemas MUST carry explicit
  versions and machine-readable compatibility constraints.
- **FR-073:** Programmatic interfaces MUST provide structured errors with stable
  codes, correlation identifiers, and safe messages.

## Non-functional requirements

### Security and privacy

- **NFR-001:** Secrets MUST come from approved secret providers or environment
  references and MUST NOT appear in configuration, logs, evidence, or errors.
- **NFR-002:** Hosted authorization MUST derive actor and tenant scope from
  authenticated claims, not caller-supplied identifiers alone.
- **NFR-003:** Cross-tenant access MUST be denied at application and storage
  boundaries and covered by negative tests.
- **NFR-004:** Security properties MUST have automated unit, integration, and
  adversarial evidence before documentation claims them.
- **NFR-005:** Dependency, artifact, and release provenance SHOULD be machine
  verifiable; release artifacts SHOULD be signed when the release process
  supports it.

### Reliability and recovery

- **NFR-010:** A process crash MUST not leave an allowed effect recorded as
  denied or an unexecuted effect recorded as successful.
- **NFR-011:** Operations with external effects MUST use stable idempotency keys
  where the sink supports them and record ambiguity when outcome is unknown.
- **NFR-012:** Storage migrations MUST be forward-tested, failure-safe, and have
  a documented backup/restore or rollback path.
- **NFR-013:** The local runtime MUST resume or clearly terminate interrupted
  approvals and runs after restart.

### Performance and resource discipline

- **NFR-020:** Governance overhead MUST be measured separately from model and
  tool latency using a reproducible benchmark harness.
- **NFR-021:** The local idle runtime SHOULD fit ordinary developer machines and
  MUST document material background resource use.
- **NFR-022:** Policy evaluation MUST have explicit timeouts and a deterministic
  failure behavior.
- **NFR-023:** Performance targets MUST be set only after baselines exist; no
  release documentation may fabricate latency or throughput claims.

### Portability and operability

- **NFR-030:** Supported operating systems and runtime versions MUST be stated
  per release and continuously tested.
- **NFR-031:** Embedded and hosted modes MUST share public behavior; backend
  differences MUST be documented and tested as explicit capabilities.
- **NFR-032:** Logs, metrics, and traces MUST correlate to run and decision IDs
  without leaking restricted content.
- **NFR-033:** `doctor`, run inspection, and safe diagnostics export MUST support
  diagnosis without exposing secrets or private trace content by default.

### Maintainability and quality

- **NFR-040:** Contract packages MUST not depend on engine, transport, UI, or
  storage implementations.
- **NFR-041:** New effect types and adapters require negative-path and bypass
  tests proportional to their risk.
- **NFR-042:** Public APIs, schemas, configurations, and persisted formats MUST
  follow the compatibility policy in `docs/RELEASE_STRATEGY.md`.
- **NFR-043:** Documentation MUST distinguish implemented, experimental, and
  planned behavior.

## Local and hosted parity

Parity means equivalent contract semantics, not identical infrastructure.

| Concern | Local | Hosted | Required invariant |
| --- | --- | --- | --- |
| Identity | OS/user and project identity | Authenticated organization identity | Actor context is explicit and evidenced. |
| Storage | Embedded provider | Postgres-compatible provider | Same schema semantics and conformance tests. |
| Policy | Local versioned files | Centrally distributed signed policy | Same decision vocabulary and binding. |
| Approval | Interactive local prompt | Authenticated workflow/API | Approval binds to exact request digest. |
| Isolation | Local sandbox capability | Managed worker/sandbox | Capability is declared; failure cannot silently downgrade. |
| Evidence | Local append-only ledger | Tenant-scoped durable ledger/export | Same envelope and correlation model. |
| Secrets | Environment/OS provider | Managed secret/KMS integration | Secret values never enter evidence. |

## Minimum complete vertical slice

The first usable release must demonstrate:

1. Initialize local state and diagnose it.
2. Run a reference engine through `ExecutionEngine`.
3. Intercept a tool request and allow, deny, or approve it.
4. Execute an allowed request through the governed dispatcher.
5. Inspect correlated append-only evidence.
6. Create and policy-promote an evidence-backed memory proposal.
7. Retrieve that memory after restart with scope enforced.
8. Export a redaction-aware SkillLoop-compatible trace through an adapter.
9. Pass unit, integration, end-to-end, negative, and adversarial tests for that
   path.

Threat and abuse cases are expected in `docs/SECURITY_MODEL.md`.
