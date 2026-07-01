# ADR-0005: Keep SkillLoop external and offline

- Status: Accepted
- Date: 2026-07-16

## Context

SkillLoop owns evaluation orchestration, replay benchmarking, datasets,
proposal generation, review workflow, and promotion recommendation. Embedding
or merging those responsibilities into the live harness
would couple two lifecycles, broaden the trusted computing base, and risk
allowing learning output to mutate production behavior.

The harness still needs a path to export evidence and receive reviewed skills,
memory proposals, policies, and other candidate artifacts.

## Decision

SkillLoop remains a separately installed, separately versioned external system.
The harness provides a versioned adapter with two one-way operations:

1. Export completed, policy-filtered canonical traces in a declared compatible
   format.
2. Import reviewed artifacts into quarantine.

Imported artifacts and recommendations receive no special trust. The harness
owns bounded quarantine, schema and digest validation, provenance and
compatibility checks, policy and approval, installation, staged activation, and
rollback controls appropriate to their type. Runtime activation is authorized
independently of SkillLoop's review or promotion recommendation.

SkillLoop has no direct write access to the live harness database, memory
provider, skill registry, policy store, secret broker, or effect executors.

## Consequences

### Positive

- Live governance remains available when SkillLoop is absent or unavailable.
- Offline experiments cannot silently change runtime behavior.
- Each repository can evolve and release independently.
- The boundary supports alternative evaluators and generic JSONL consumers.
- Export policy can minimize sensitive training/evaluation data.

### Costs

- Contract mapping and compatibility maintenance are required.
- Feedback is asynchronous rather than immediate.
- Some SkillLoop-native information may be represented as explicit adapter
  extensions or documented as lossy.
- Artifact review and installation add operational steps.

## Guardrails

- Only terminal or explicitly checkpointed ledger ranges are exported. Those
  ranges are append-only through harness application interfaces and
  tamper-evident within the documented threat model.
- Export bundles carry schema versions, source ranges, filter digests, counts,
  and aggregate digests.
- Secrets and unrelated tenant data are denied by default.
- Imports are bounded and quarantined before parsing executable content.
- SkillLoop evaluation success cannot grant permissions or approval.
- SkillLoop promotion recommendations cannot authorize installation or runtime
  activation.
- No adapter code imports SkillLoop internals into the kernel.
- The harness does not deploy a general evaluation, replay-benchmarking,
  dataset-management, proposal-generation, or model-assisted evaluation
  pipeline.
- Adapter unavailability cannot weaken tool or memory governance.

## Alternatives rejected

- **Merge SkillLoop into the monorepo:** expands scope and couples online and
  offline trust boundaries.
- **Allow SkillLoop direct database access:** bypasses canonical commands,
  policy, and evidence creation.
- **Automatically apply successful proposals:** evaluation is not authorization
  and may be poisoned, incompatible, or regress other workloads.
- **Reimplement all SkillLoop features in the harness:** duplicates a separate
  product and distracts from live governance.
