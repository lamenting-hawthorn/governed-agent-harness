# ADR-0005: Keep SkillLoop external and offline

- Status: Accepted
- Date: 2026-07-16

## Context

SkillLoop already addresses trace normalization, evaluation, replay, proposal
review, and dataset generation. Embedding or merging it into the live harness
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

Imported artifacts receive no special trust. They pass schema, digest,
provenance, compatibility, policy, evaluation, approval, installation, staged
activation, and rollback controls appropriate to their type.

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

- Only terminal or explicitly checkpointed immutable ledger ranges are exported.
- Export bundles carry schema versions, source ranges, filter digests, counts,
  and aggregate digests.
- Secrets and unrelated tenant data are denied by default.
- Imports are bounded and quarantined before parsing executable content.
- SkillLoop evaluation success cannot grant permissions or approval.
- No adapter code imports SkillLoop internals into the kernel.
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
