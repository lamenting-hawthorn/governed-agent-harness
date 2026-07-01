# Security Model

## Status and intent

This document defines required security properties for Governed Agent Harness.
It does not claim that the current repository implements or has independently
verified them. A release may claim a property only when the corresponding test,
operational evidence, and documented limitation exist.

The harness assumes model output, retrieved content, skills, tool arguments,
and external data are untrusted. Governance is enforced by trusted code around
the execution engine, never by asking a model to comply.

## Security objectives

The system must:

- authenticate external callers and establish an explicit actor context;
- authorize every protected read, write, administrative action, and effect;
- evaluate policy synchronously before an effect can occur;
- keep tenant, user, project, and session data within their declared scope;
- prevent secrets and sensitive data from entering prompts, logs, or evidence
  unless explicitly permitted;
- preserve attributable, tamper-evident evidence for governed decisions;
- treat memory promotion, skill installation, and learning import as effects;
- fail closed when an enforcement dependency is unavailable; and
- expose honest capability and enforcement limits.

Availability, model correctness, and complete prevention of prompt injection
are not guaranteed. Controls reduce risk and make failures observable.

## Trust boundaries

| Boundary | Trusted responsibility | Untrusted input |
| --- | --- | --- |
| API/CLI ingress | Parse, authenticate, rate-limit, assign request ID | User input, headers, files |
| Identity service | Verify credentials, issue actor context | Tokens and identity assertions |
| Governance kernel | Validate contracts, invoke policy, coordinate effects | Engine events and model output |
| Policy engine | Produce deterministic decision from versioned inputs | Requested action and context |
| Execution engine | Propose messages and tool calls only | Model providers and responses |
| Tool broker | Enforce the decision and mediate capabilities | Tool name, arguments, output |
| Sandbox | Restrict process, filesystem, network, time, and resources | Executed code and dependencies |
| Memory service | Enforce evidence, scope, retention, and revision rules | Candidate memories and retrieval queries |
| Ledger | Append attributable events and integrity metadata | Event payloads |
| Providers/adapters | Translate versioned contracts without widening authority | Remote systems and protocol data |

The process hosting a tool or adapter is trusted only for the capabilities it
must hold. A provider credential must not grant broader access than the
associated actor, tenant, and operation require.

## Enforcement tiers

Every engine and adapter publishes a capability manifest. The tier is asserted
per capability, not per brand or integration.

| Tier | Permitted behavior | Security meaning |
| --- | --- | --- |
| Observe | Receive post-hoc events | Audit visibility only; cannot prevent effects |
| Advise | Add context or recommendations | May influence behavior; cannot enforce it |
| Gate | Intercept before an effect and synchronously allow, deny, transform, or request approval | Preventive control for covered effects |
| Isolate | Gate and execute the effect inside a constrained boundary | Preventive control plus blast-radius reduction |

The UI, CLI, API, and documentation must not label Observe or Advise as
enforcement. Unsupported effect classes must be reported explicitly. MCP is a
transport and does not prove that host-native tools are gated.

## Identity, authentication, and authorization

`ActorContext` is established at a trusted ingress and includes immutable
identifiers for tenant, actor, authentication method, roles, project, session,
and correlation ID. Callers cannot supply trusted roles or tenant membership in
ordinary request bodies.

Requirements:

1. Local single-user mode uses an explicit local identity and records that the
   assurance level is local, not enterprise authentication.
2. Hosted mode verifies issuer, audience, signature, expiry, and revocation
   policy for tokens. Administrative operations require step-up or equivalent
   strong authentication.
3. Authorization is deny-by-default and evaluates tenant, resource, action,
   role, ownership, policy version, and requested effect.
4. Services use separate least-privilege identities. Database superuser or
   service-role credentials are not used on tenant request paths.
5. Tenant scope is applied in application authorization and storage
   enforcement. Tests must prove cross-tenant denial.
6. Background jobs carry a delegated service identity and original actor or
   system provenance; they never inherit ambient authority silently.

## Policy before effect

An effect is any action that changes external or durable state, discloses
protected data, spends a controlled budget, or changes future agent behavior.
Examples include tool execution, network access, file writes, outbound
messages, database mutation, secret access, memory promotion, skill install,
policy change, and learning import.

The only valid effect path is:

1. Validate a versioned `ToolRequest` or equivalent effect request.
2. Resolve actor, resource, capability, data classification, and risk context.
3. Record the request in the ledger.
4. Evaluate the exact normalized request with a versioned policy.
5. Record `PolicyDecision` and its reason.
6. For approval, bind approver, decision, expiry, and request hash.
7. Execute only the approved request hash through the broker or sandbox.
8. Record outcome, bounded output metadata, and integrity linkage.

Changing tool arguments, identity, policy, target, or capability after approval
invalidates the decision. Timeouts, policy errors, missing identity, malformed
requests, and unavailable approval state deny the effect. Read-only model
generation may continue only if doing so cannot cause the protected effect.

## Tool and sandbox boundary

Tools are registered by immutable ID and version with input/output schemas,
declared effects, risk class, and required capabilities. The broker rejects
unknown tools, undeclared effects, invalid inputs, and direct execution paths.

Isolated execution must define and test:

- read-only base filesystem plus explicit writable mounts;
- canonical path validation at the filesystem sink;
- network deny-by-default with destination and protocol allowlists;
- no inherited environment or host credentials;
- scoped secret injection for the shortest practical lifetime;
- CPU, memory, process, output-size, and wall-clock limits;
- non-root execution and platform-appropriate syscall/process isolation;
- cancellation and cleanup behavior; and
- an honest capability report when the platform cannot provide a control.

Sandboxing reduces impact; it is not treated as a perfect containment boundary.
High-risk deployments should use operating-system or virtual-machine isolation
appropriate to their threat model.

## Secrets, PII, and sensitive content

Secrets are referenced by opaque handles. They are resolved after authorization
at the execution boundary and must not be placed in model context, policy
reason text, command-line arguments when avoidable, event payloads, or logs.
Secret values must be redacted using exact-value and structured-field controls.

Ingress and egress classify data as public, internal, confidential, restricted,
or secret. Policy controls whether each class may be sent to a model provider,
tool, tenant scope, or telemetry sink. Redaction occurs before external export.
Logs record classification and redaction outcomes, not the removed value.

PII handling follows data minimization, purpose limitation, bounded retention,
and deletion requirements in `DATA_GOVERNANCE.md`.

## Supply-chain controls

- Dependencies and container images are pinned or locked and scanned in CI.
- Release artifacts have checksums, provenance, and signatures when the release
  process supports them.
- Skills and adapters declare publisher, version, integrity hash, permissions,
  and compatibility. Installation never grants permissions automatically.
- Build and release credentials are isolated, short-lived, and least privilege.
- Untrusted plugins execute at the lowest supported tier and isolation level.
- Critical dependency updates require review and regression testing.

## Failure policy

Security-critical components fail closed. Specifically, an unavailable policy
engine, invalid identity, lost approval state, ledger precondition failure, or
request-integrity mismatch prevents the effect. Telemetry export may fail open
only when the authoritative local evidence append succeeds and a bounded retry
queue is available. Queue exhaustion is surfaced as degraded readiness.

## Required evidence before security claims

A release must link each claimed property to:

- the implementation boundary that enforces it;
- positive and negative tests;
- an adversarial test where relevant;
- known unsupported platforms or effect classes;
- operational detection and response; and
- the release/version in which it was verified.

See `THREAT_MODEL.md`, `TESTING_STRATEGY.md`, and `DEFINITION_OF_DONE.md`.
