# ADR-0003: Use a contract-first protocol

- Status: Accepted
- Date: 2026-07-16

## Context

The harness must coordinate a TypeScript kernel, a Pi execution adapter,
multiple transports, storage backends, optional external systems, and Python
consumers such as SkillLoop adapters. Handwritten types in each package would
drift, and TypeScript types do not validate persisted or untrusted data.

Contracts also become durable history because ledger events, memory records,
skill manifests, and evaluation results must remain readable across upgrades.

## Decision

Use versioned JSON Schema as the canonical definition for wire and persisted
contracts. Generate TypeScript static types and runtime validators plus Python
validation models from the same schemas.

All public and persisted envelopes carry a semantic `schemaVersion`. Contract
changes run compatibility analysis and shared positive/negative fixtures.
Readers use pure upcasters for supported historical representations without
rewriting original ledger events.

Domain-only internal objects may remain native TypeScript when they never cross
a package/process/persistence boundary.

## Consequences

### Positive

- TypeScript and Python consumers share one authority.
- Boundary validation is executable and testable.
- Compatibility changes are visible before release.
- External adapters can implement the protocol without importing the kernel.
- Historical fixtures make upgrade behavior reproducible.

### Costs

- Schema design and generator maintenance add build complexity.
- Some TypeScript types are less expressive than native-only models.
- Generated output must be reviewed through source schemas rather than edited.
- Upcasters and compatibility fixtures become long-lived maintenance work.

## Guardrails

- Generated files are reproducible and checked for drift in CI.
- Unknown properties are rejected for security-sensitive messages unless an
  explicit extension map exists.
- Enums are closed unless unknown-value behavior is specified.
- Contract packages do not depend on runtime packages.
- A major schema change requires migration documentation and compatibility
  tests.

## Alternatives rejected

- **TypeScript types as authority:** no runtime validation and poor Python
  interoperability.
- **Python models as authority:** makes the TypeScript execution path dependent
  on a Python-centric schema workflow.
- **Protocol Buffers only:** strong IDL, but less natural for manifests, MCP,
  HTTP JSON, and contributor-authored skill schemas.
- **Handwritten per-language models:** inevitable semantic drift.
