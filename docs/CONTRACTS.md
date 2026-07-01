# Contracts

## Contract authority

JSON Schema is the canonical definition for public messages, persisted event
payloads, manifests, and adapter interchange. TypeScript types and Python models
are generated artifacts and must not be edited manually.

The contract build must:

1. Validate every schema against the selected JSON Schema draft.
2. Reject unresolved references and duplicate identifiers.
3. Generate TypeScript runtime validators and static types.
4. Generate Python validation models.
5. Run shared positive and negative fixtures against both languages.
6. Detect compatibility changes before publication.

Static TypeScript types are not boundary validation. Every untrusted or
persisted value is checked by a generated runtime validator.

## Envelope

All commands, events, and integration records use a common envelope:

```ts
type Envelope<TType extends string, TPayload> = {
  schemaVersion: `${number}.${number}.${number}`;
  id: string;                 // UUIDv7
  type: TType;
  occurredAt: string;         // RFC 3339 UTC
  recordedAt: string;         // assigned by storage
  tenantId: string;
  actorId: string;
  runId?: string;
  sequence?: number;          // required for run events
  correlationId: string;
  causationId?: string;
  idempotencyKey?: string;
  payloadDigest: string;      // canonical JSON digest
  payload: TPayload;
  metadata: {
    producer: string;
    producerVersion: string;
    traceId?: string;
    sensitivity?: "public" | "internal" | "confidential" | "restricted";
  };
};
```

Unknown properties are rejected for security-sensitive messages unless the
schema explicitly defines an extension map. Timestamps are informational for
ordering; the ledger sequence is authoritative within a run.

Canonical JSON serialization must be deterministic before hashing. Digests
identify exact content, not semantic equivalence.

## Identity and scope

```ts
type ActorContext = {
  tenantId: string;
  actorId: string;
  subject: string;
  roles: string[];
  projectId?: string;
  workspaceId?: string;
  sessionId: string;
  authenticationMethod: "local-os" | "oidc" | "service";
  authenticationTime: string;
  trustLevel: "local-owner" | "human" | "service" | "untrusted";
};
```

`ActorContext` is internal authenticated context. Transports do not accept it
as a user-supplied JSON object. They construct it from verified credentials and
pass it out-of-band to command handlers.

## Agent events

The stable event taxonomy includes:

- `run.created`, `run.started`, `run.completed`, `run.failed`, `run.cancelled`
- `message.received`, `message.emitted`
- `model.requested`, `model.completed`, `model.failed`
- `tool.proposed`, `policy.decided`, `approval.requested`,
  `approval.resolved`, `effect.started`, `effect.completed`, `effect.failed`
- `context.retrieved`, `checkpoint.saved`
- `memory.proposed`, `memory.promoted`, `memory.rejected`,
  `memory.superseded`, `memory.expired`
- `skill.resolved`, `skill.activated`, `skill.rejected`
- `evaluation.completed`, `artifact.imported`, `artifact.rejected`

Model prompts, secrets, and unrestricted tool output are not mandatory event
fields. Sensitive payloads are stored only according to data policy and may be
represented by a digest plus a protected blob reference.

## Tool request

```ts
type ToolRequest = {
  requestId: string;
  runId: string;
  turnId: string;
  tool: {
    namespace: string;
    name: string;
    version: string;
  };
  arguments: unknown;
  argumentsDigest: string;
  declaredEffects: Array<{
    kind: "read" | "write" | "network" | "execute" | "message" | "secret";
    resource: string;
  }>;
  riskHint?: "low" | "medium" | "high" | "critical";
  idempotencyKey: string;
};
```

The kernel validates `arguments` against the installed tool schema and computes
its own digest. Engine-provided digests, effects, and risk hints are advisory
until verified. Tool names are resolved to immutable installed versions.

## Policy decision

```ts
type PolicyDecision = {
  decisionId: string;
  requestId: string;
  requestDigest: string;
  policyBundleId: string;
  policyBundleVersion: string;
  outcome: "allow" | "deny" | "require_approval" | "redact" | "isolate";
  reasonCodes: string[];
  publicReason: string;
  constraints?: {
    timeoutMs?: number;
    networkAllowlist?: string[];
    filesystemRoots?: string[];
    outputBytes?: number;
    secretRefs?: string[];
  };
  replacementArguments?: unknown;
  expiresAt?: string;
};
```

`redact` is a transformation, not authorization. The replacement request is
validated, re-digested, and evaluated again. `isolate` authorizes execution only
through an executor satisfying the requested isolation capability.

## Approval

An approval record binds:

- tenant, actor, approver, and run;
- exact request and policy decision digests;
- permitted constraints;
- creation and expiry times;
- approve or deny outcome;
- authentication method and optional signature.

Approvals cannot be reused for changed arguments, another tenant, another tool
version, or after expiry. “Approve all” is implemented as a separately created,
scoped policy grant, never as digest-free approval.

## Evidence envelope

```ts
type EvidenceEnvelope<T> = Envelope<string, T> & {
  previousDigest?: string;
  eventDigest: string;
  retentionClass: string;
  blobRefs?: Array<{
    digest: string;
    mediaType: string;
    size: number;
    encryptionKeyRef?: string;
  }>;
};
```

The event digest covers stable envelope fields, payload, and previous digest.
Storage-assigned fields are included after append. A hash chain provides
tamper-evidence within its threat model, not absolute immutability.

## Memory contracts

```ts
type EvidenceReference = {
  eventId: string;
  eventDigest: string;
  blobDigest?: string;
  span?: { start: number; end: number; unit: "utf8-byte" | "codepoint" };
};

type MemoryProposal = {
  proposalId: string;
  type: "semantic" | "episodic" | "procedural";
  content: unknown;
  contentDigest: string;
  evidence: EvidenceReference[];
  scope: { tenantId: string; actorId?: string; projectId?: string };
  confidence: number;
  authority: "observed" | "user_asserted" | "derived" | "imported";
  sensitivity: string;
  retention: { class: string; expiresAt?: string };
  proposedBy: { kind: "kernel" | "actor" | "adapter"; id: string };
};

type MemoryRecord = MemoryProposal & {
  memoryId: string;
  revision: number;
  status: "active" | "superseded" | "expired" | "deleted";
  policyDecisionId: string;
  validFrom: string;
  validTo?: string;
  supersedes?: string[];
};
```

A record never loses its evidence. Correction creates a new revision and an
explicit supersession event. Deletion follows retention requirements while
preserving the minimal audit tombstone allowed by policy.

## Skill manifest

```ts
type SkillManifest = {
  schemaVersion: string;
  name: string;
  version: string;
  description: string;
  publisher: { id: string; name: string };
  packageDigest: string;
  entrypoint: string;
  inputSchema: string;
  outputSchema: string;
  permissions: PermissionRequest[];
  supportedEngines: Array<{ name: string; versionRange: string }>;
  requiredCapabilities: string[];
  risk: "low" | "medium" | "high" | "critical";
  tests: Array<{ name: string; fixture: string; expected: string }>;
  provenance: { source: string; revision: string; builtAt: string };
  signatures?: Array<{ keyId: string; algorithm: string; value: string }>;
};
```

A valid signature proves package association with a key; trust in that key is
a separate policy decision.

## Capability manifest

Every adapter publishes a machine-readable manifest:

```ts
type CapabilityManifest = {
  component: { kind: string; name: string; version: string };
  protocolVersions: string[];
  capabilities: Record<string, {
    version: string;
    level?: "observe" | "advise" | "gate" | "isolate";
    limitations?: string[];
  }>;
};
```

Startup compares required capabilities with the selected components. Missing
required capabilities are fatal. Optional capabilities are disabled explicitly
and recorded; they are never silently emulated.

## Evaluation result

```ts
type EvalResult = {
  evaluationId: string;
  runId: string;
  evaluator: { name: string; version: string; configDigest: string };
  subjectDigest: string;
  metrics: Record<string, number | boolean | string>;
  evidence: EvidenceReference[];
  outcome: "pass" | "fail" | "inconclusive" | "error";
  completedAt: string;
};
```

An evaluation distinguishes `fail` from infrastructure `error` and insufficient
evidence `inconclusive`. Model-judged metrics identify the model, prompt digest,
sampling parameters, and raw evidence policy.

## Commands versus events

- A **command** requests a state transition and includes an idempotency key.
- An **event** states that something occurred and is immutable.
- A **query result** is a projection and carries its ledger position.

Commands are not appended as successful events until authorized validation has
occurred. Rejections may be recorded as separate events with sanitized fields.

## Versioning policy

Contract packages use semantic versioning:

- Patch: documentation, generator, or fixture change with identical accepted
  wire values.
- Minor: backward-compatible optional fields, new event types, or new enum
  values only where consumers are defined to tolerate them.
- Major: removed/renamed fields, stricter validation of previously valid data,
  semantic changes, or changed required behavior.

Enums are closed by default. Extensible discriminator fields must explicitly
define unknown-value behavior.

Every persisted envelope declares its schema version. Producers emit one
configured version. Consumers declare a supported range and reject unsupported
majors with `CONTRACT_VERSION_UNSUPPORTED`.

## Compatibility workflow

Every contract change requires:

1. Updated canonical schema and fixtures.
2. Generated TypeScript and Python output with no manual delta.
3. Compatibility diff against the latest released schema.
4. Round-trip tests in both languages.
5. Upcaster and historical fixture when reading an older representation.
6. Changelog entry and migration note.

Upcasters are pure, deterministic functions. They preserve original event
digests and expose the upgraded view separately; they do not rewrite the
ledger.

## Error contract

Public boundaries return stable structured errors:

```ts
type HarnessError = {
  code: string;
  message: string;
  retryable: boolean;
  correlationId: string;
  details?: Record<string, string | number | boolean>;
};
```

`details` is allowlisted per error code. Validation errors may identify field
paths but must not echo secrets or unrestricted input. Internal causes remain
in protected diagnostics.

## Minimum conformance suites

- Envelope canonicalization and digest fixtures.
- Schema acceptance and rejection parity across TypeScript and Python.
- Adapter capability negotiation.
- Idempotent command replay and digest mismatch conflicts.
- Unknown version and unknown event handling.
- Tenant-scope negative tests.
- Approval request-digest binding.
- Memory-without-evidence rejection.
- Skill permission escalation rejection.

See [ADR-0003](adr/0003-contract-first-protocol.md).
