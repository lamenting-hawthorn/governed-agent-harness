# ADR-0004: Require local and hosted storage parity

- Status: Accepted
- Date: 2026-07-16

## Context

The product must be useful for one person without infrastructure and capable of
operating in a hosted multi-tenant environment. Separate local and hosted domain
models would create incompatible behavior, untested migration paths, and a demo
that cannot graduate to production.

PGlite provides an embedded Postgres-compatible local path. Hosted deployments
need managed Postgres features, connection scaling, database-enforced tenant
controls, and durable operations.

## Decision

Define one storage port and behavioral conformance suite. Implement it first for
PGlite and Postgres. Both backends use the same logical schema, migrations,
transactions, event ordering, idempotency rules, projection semantics, and
contract fixtures.

Backend-specific capabilities may differ only when declared in capability
manifests and cannot change governance semantics. Local mode does not claim
hosted multi-tenant isolation; hosted mode adds database roles/policies as
defense in depth.

Migration sources are shared. Backend-specific SQL is isolated, justified, and
tested in both upgrade paths.

## Consequences

### Positive

- A local installation exercises the real domain model.
- Projects can move from embedded to hosted storage through documented export
  and import rather than semantic conversion.
- One conformance suite exposes backend drift.
- Contributors can run meaningful integration tests locally.

### Costs

- Features unavailable in PGlite cannot become unconditionally required.
- Concurrency and extension differences need explicit tests.
- Hosted scale optimizations must preserve the shared behavior.
- Two real database implementations increase CI time.

## Required parity

- append-only ledger ordering and optimistic concurrency;
- transactional event plus projection updates;
- command idempotency and digest conflicts;
- memory revision, supersession, expiry, and deletion;
- skill and approval state transitions;
- migration versioning and restartability;
- tenant-qualified keys and query interfaces;
- consistent contract errors.

Performance parity is not required. Semantic parity is.

## Guardrails

- The full storage conformance suite runs against both backends.
- Hosted tenant-isolation tests use separate database roles and adversarial
  cross-tenant queries.
- Local files default to restricted permissions and loopback-only access.
- Export/import verifies counts and aggregate digests.
- A backend capability cannot authorize an effect or bypass a ledger append.

## Alternatives rejected

- **SQLite locally, unrelated Postgres schema hosted:** simpler initial setup but
  likely semantic and SQL drift.
- **Postgres required everywhere:** high setup cost contradicts plug-and-play
  local use.
- **PGlite only:** insufficient operational and isolation posture for hosted
  enterprise use.
- **Provider-specific domain models:** couples the kernel to storage products.
