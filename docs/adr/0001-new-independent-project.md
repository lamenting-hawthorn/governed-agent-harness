# ADR 0001: Build a New Independent Governed Agent Harness

- **Status:** Accepted
- **Date:** 2026-07-16

## Context

Governed Agent Architecture contains useful memory, retrieval, tracing, and
governance concepts. SkillLoop contains useful evaluation, replay, proposal,
review, and training-artifact concepts. Both projects have their own purpose,
history, implementation assumptions, and users.

Combining them directly would couple an online runtime to an asynchronous
learning system, preserve Hermes- and implementation-specific decisions, and
make migration risk part of the new product's foundation. Extending only one
project would also make the other appear subordinate and would blur ownership
of live enforcement versus reviewed improvement.

The desired product is a local-first governed harness whose execution engine is
replaceable and whose contracts can support OSS use now and enterprise
deployment later.

## Decision

Create a new, independent repository for the Governed Agent Harness.

- Governed Agent Architecture and SkillLoop remain unchanged and independent.
- The new project may adapt their architectural invariants with attribution,
  but it does not copy large implementations.
- Interoperability occurs through versioned adapters and artifacts.
- The new repository owns the governance kernel, execution-engine boundary,
  policy path, evidence ledger, governed memory lifecycle, skill model, and
  product interfaces.
- SkillLoop is an optional evaluation and learning integration. It cannot
  mutate the live runtime automatically.
- GAA may become an optional memory or runtime integration, but it is not a
  required dependency.

## Consequences

### Positive

- Contracts can be designed around the desired trust boundaries rather than
  inherited compatibility constraints.
- Online execution and asynchronous learning remain separate failure and trust
  domains.
- Existing users and repositories are not disrupted.
- The project can expose honest optional adapters instead of hidden coupling.
- OSS packaging and enterprise extension points can evolve together from a
  clean boundary.

### Costs

- A third repository requires independent release, documentation, and support.
- Concepts adapted from the existing projects must be reconciled and tested.
- Interoperability needs maintained schemas and compatibility fixtures.
- Early feature progress may appear slower because foundational contracts are
  implemented before broad integrations.

## Alternatives considered

### Merge GAA and SkillLoop

Rejected because it joins different runtime, trust, release, and operational
concerns and increases migration risk.

### Turn GAA into the new harness

Rejected because current engine and framework assumptions would shape the
kernel, and preserving compatibility would compete with runtime neutrality.

### Extend SkillLoop into a live runtime

Rejected because evaluation and reviewed learning should not become the live
effect-enforcement boundary.

### Build only an add-on or MCP server

Rejected because an advisory integration cannot guarantee interception of
host-native effects. MCP remains a useful transport, not the complete
governance boundary.

## Guardrails

- Do not edit the source repositories as part of this project's implementation.
- Preserve attribution for adapted ideas and contracts.
- Validate integrations using public, versioned boundaries.
- Keep the default local path useful without either external project.
