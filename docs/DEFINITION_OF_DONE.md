# Definition of Done

## Purpose

“Done” means behavior is implemented, tested, documented, operable, and honest
about limitations. A merged pull request, passing happy-path test, or working
demo alone is not done.

## Change-level definition

A change is done only when all applicable items are satisfied:

- The user outcome and acceptance criteria are explicit.
- Public and persisted contracts are versioned and backward compatibility is
  preserved or a migration and compatibility window is documented.
- Inputs are validated at boundaries; effects are validated at sinks.
- Protected effects pass through the synchronous policy gate.
- Tenant, actor, project, and session scope are explicit and tested.
- Sensitive fields have classification, redaction, retention, and egress rules.
- Evidence, reason codes, correlation, and useful metrics exist without logging
  secrets or unrestricted content.
- Unit, negative-path, integration, contract, and adversarial tests match risk.
- Failure, timeout, retry, cancellation, idempotency, and concurrency behavior
  are implemented and tested.
- Documentation describes actual behavior and limitations.
- An independent reviewer has examined security and maintainability for
  non-trivial changes.
- Formatting, lint, type, test, link, secret, dependency, and diff checks pass.
- Rollout, rollback, migration, and operator impact are documented when needed.
- No unrelated files or generated/private artifacts enter the change.

## Security invariant gate

No release may claim Gate or Isolate support for an effect class unless the
conformance suite proves 100% of declared execution paths invoke policy before
the effect. Known bypasses block the claim and stable release.

Additionally:

- cross-tenant access tests have zero unexpected successes;
- secret-canary tests have zero leaks across supported sinks;
- approval mutation/replay tests have zero unauthorized effects;
- memory promotion without evidence or policy has zero successful paths;
- learning import cannot mutate live runtime without validated, versioned
  installation and required approval; and
- the evidence integrity verifier detects fixture mutation, deletion, reorder,
and sequence gaps.

## Phase 4 durable-state exit gate

The lifecycle/effect authority and actor-scoped read-only retrieval are now
joined by the bounded Phase 4.3 evidence-backed promotion path. Its real
PostgreSQL gate proves that:

- promotion without resolvable same-tenant evidence and an exact bound policy
  decision/approval has zero successful paths;
- create, revision, supersession, tombstone, retention, expiry, idempotency,
  replay, restart, and concurrent conflict behavior preserve one authoritative
  history;
- runtime roles cannot directly mutate records, invoke authority-only
  transitions, forge scope, or bypass forced RLS; and
- canonical evidence append and authoritative revision persistence are atomic,
  while projections remain rebuildable and never become authorization truth.

Durable skills remain a separate Phase 4 deliverable. Before Phase 5 starts,
skills must either pass their own lifecycle/integrity/restart gate or be removed
from the Phase 4 completion boundary by an explicit reviewed roadmap change.

## First usable release gate

The initial release is done when a new contributor can, from a clean supported
environment:

1. Install and initialize local mode using documented commands.
2. Run a reference execution engine without an external database.
3. Exercise allow, deny, and approval for a tool request.
4. Confirm only the policy-bound request executes.
5. Inspect correlated, replayable evidence for request through outcome.
6. Promote an evidence-backed memory and retrieve it after restart.
7. Confirm rejected, expired, deleted, and cross-scope memory is not retrieved.
8. Export and schema-validate a SkillLoop-compatible trace.
9. Run `doctor` and receive an accurate report with no secret disclosure.
10. Uninstall or remove local state through an explicit, safe workflow.

The workflow must run in CI end to end. Installation success is measured on all
documented supported platforms; unsupported platforms are named.

## OSS readiness gate

- README, architecture, security model, threat model, contribution guide,
  support/security reporting, and release notes agree with implementation.
- License and third-party attribution are complete before distribution.
- Fresh-install and upgrade documentation is tested.
- Public APIs and extension points have examples and conformance tests.
- Issue/PR templates and governance identify maintainers and response paths.
- Release artifacts are reproducible enough to verify contents, include
  checksums and SBOM, and have provenance/signatures when supported.
- There are no committed secrets, private data, machine-specific paths, build
  caches, or unexplained generated artifacts.
- Dependency vulnerabilities are triaged; unresolved critical/high findings
  require documented risk acceptance and cannot contradict security claims.

## Operational readiness gate

Before hosted production:

- approved service indicators and objectives exist with measured baselines;
- readiness distinguishes mandatory failures from optional degradation;
- alerts are actionable and mapped to exercised runbooks;
- backup and isolated restore tests meet approved RPO/RTO;
- forward and rollback/recovery migration exercises pass on representative
  data volume;
- key and credential rotation is tested;
- deletion completes within its approved objective across primary, derived,
  cache, export, provider, and backup lifecycle;
- capacity, load, soak, cancellation, queue-pressure, and provider-outage tests
  meet agreed thresholds; and
- incident ownership, escalation, and evidence-preservation procedures exist.

## Enterprise readiness gate

Enterprise-ready is not a synonym for “supports Postgres.” It additionally
requires verified tenant isolation, external authentication, least-privilege
service authorization, administrative audit, retention/deletion controls,
region/provider documentation, upgrade compatibility, disaster recovery,
support ownership, and an appropriate independent security review. Compliance
or certification claims require their own evidence and are outside this gate.

## Evidence of completion

Each release records the commit, dependency lock, schema and policy versions,
test commands/results, supported environment matrix, migration result, artifact
digests, known limitations, security findings disposition, and approvers.
Unverified work is marked experimental; it is not described as production-safe.
