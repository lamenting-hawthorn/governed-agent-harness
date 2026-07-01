# Data Governance

## Principles

Governed Agent Harness uses data minimization, explicit purpose, tenant and
actor scope, evidence-backed derivation, bounded retention, user correction,
and verifiable deletion. These are implementation requirements, not present-day
compliance claims.

## Data classes

| Class | Examples | Default handling |
| --- | --- | --- |
| Public | Public documentation and user-designated public content | May be processed by approved providers |
| Internal | Run metadata, non-sensitive configuration | Tenant-scoped; no public export |
| Confidential | Prompts, files, tool outputs, memory content | Encrypt, minimize, restrict egress and access |
| Restricted | PII, financial/legal data, private repository content | Explicit purpose and provider policy; short retention |
| Secret | Tokens, passwords, private keys, recovery codes | Opaque reference only; never persist in prompts or telemetry |

Deployments may add classifications but cannot weaken these defaults silently.

## Data inventory and lineage

Every persisted dataset has an owner and records:

- schema and version;
- purpose and lawful/authorized use where applicable;
- classification and tenant scope;
- source, ingestion time, and integrity hash;
- storage location, subprocessors/providers, and encryption state;
- retention rule and deletion mechanism;
- derived projections, indexes, caches, exports, and backups; and
- roles permitted to access or administer it.

Derived memory and evaluation artifacts retain lineage to source evidence.
Exports carry classification, scope, schema version, and provenance.

## Evidence and memory lifecycle

Raw evidence is append-only through application interfaces, access-controlled,
and tamper-evident within the documented threat model. It is retained only as
long as its declared purpose requires. These properties do not override
authorized privacy deletion or administrative operations; deletion uses an
authorized tombstone and removes or cryptographically erases governed payloads
while preserving the minimum non-sensitive proof of the operation allowed by
policy.

A `MemoryProposal` contains evidence references, exact evidence spans where
possible, extractor/version provenance, proposed scope, type, confidence,
authority, classification, and retention. Promotion requires a versioned policy
decision. High-risk classes require human review. Committed memories are
versioned projections; correction and conflict create superseding records.

Retrieval applies authorization and scope filtering before ranking. Results
carry source, revision, trust, freshness, and classification metadata. The
model receives only content permitted for its provider and current purpose.

## Collection and provider egress

Collect only fields required for the declared operation. Optional diagnostics
are opt-in where they may contain content. Before sending data to a model,
telemetry provider, external tool, or learning system, the egress gate checks
classification, destination, purpose, tenant policy, region constraints, and
redaction. Provider defaults must not permit training on customer content when
that can be disabled.

## Retention schedule

Defaults must be explicit in configuration and visible to the user. A hosted
deployment must not use unlimited retention by accident.

| Dataset | Required retention behavior |
| --- | --- |
| Active session state | Short-lived; expire after session/recovery window |
| Raw prompts and tool outputs | Off or bounded by tenant policy; content logging disabled by default |
| Evidence ledger metadata | Retain per audit policy; minimize payload content |
| Approved memory | Until expiry, supersession, or authorized deletion |
| Rejected proposal | Short retention sufficient for review/audit, then delete payload |
| Telemetry | Aggregate where possible; bounded operational window |
| Backups | Encrypted, access-controlled, fixed expiry with tested deletion |
| Exported datasets | Explicit owner, location, purpose, and expiry |

Retention jobs are idempotent, observable, and fail visibly. Legal hold, where
implemented, is authorized, scoped, time-bounded, and audited.

## Access, correction, export, and deletion

Authorized users and administrators can discover what governed data exists for
their scope, export it in a versioned machine-readable format, correct derived
memory, and request deletion subject to documented obligations.

Deletion workflow:

1. Authenticate and authorize the requester and scope.
2. Record a deletion request without duplicating sensitive payloads.
3. Stop new retrieval and processing immediately through a tombstone.
4. Delete primary payloads, derived records, indexes, caches, and queued work.
5. Propagate to processors and scheduled exports.
6. Expire backups according to the documented backup window; prevent restore
   from silently resurrecting tombstoned records.
7. Record non-sensitive completion evidence and report exceptions.

Deletion has an explicit service objective and an end-to-end verification test.

## Tenant isolation

Every tenant-owned row, object, cache key, event, queue item, search index, and
backup partition carries tenant identity. Scope is derived from trusted actor
context, not caller-provided filters. Hosted storage uses defense in depth:
application authorization plus database/object-store enforcement and separate
administrative paths. Cross-tenant test matrices are release-blocking.

## Encryption and keys

Use modern transport encryption for network paths and platform-supported
encryption at rest. Production keys are separated by environment, stored in a
managed secret/KMS system, access-controlled, rotated, and recoverable through a
tested process. Key identifiers may be logged; key material may not. Sensitive
field encryption is added where storage-admin access is in the threat model.

## Non-production and analytics

Production content is not copied into development or CI. Test fixtures are
synthetic. Analytics uses aggregated or pseudonymized data when possible and
must not reconstruct prompts, identities, or tenant activity. Debug exports are
time-bounded, encrypted, access-logged, and deleted after the incident.

## Accountability

Schema, retention, new provider, or new data-purpose changes require security
and privacy review. The repository documents implemented behavior and known
limitations. Regulatory certifications or legal compliance are not claimed
without the applicable independent process and deployment evidence.
