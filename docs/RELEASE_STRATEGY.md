# Release Strategy

## Goals

Releases must let users determine what is stable, what is compatible, what is
enforced, and how to recover. The project advances through evidence-based
maturity levels rather than declaring production readiness from feature count.

## Versioned surfaces

The following surfaces are versioned independently where appropriate:

- Distribution and package versions.
- Canonical operation/API contracts.
- JSON Schemas and normalized events.
- Persisted storage schemas and migration history.
- Policy language and decision model.
- Execution-engine, storage-provider, evaluator, skill, and MCP adapter
  contracts.
- CLI configuration and lockfiles.
- Evidence export and replay formats.

All persisted and transmitted objects include a schema identifier and version.

## Semantic versioning

Packages use Semantic Versioning after their first stable release.

- **Patch:** compatible bug or security fix with no intentional public contract
  change.
- **Minor:** backward-compatible capability or additive optional field.
- **Major:** incompatible API, schema, policy, configuration, persistence, or
  behavior change.

Before `1.0.0`, minor releases may contain breaking changes only when clearly
called out, paired with migration guidance, and confined to surfaces explicitly
marked experimental. Stable contract packages should reach `1.0.0` before the
overall product claims stable third-party integration.

## Compatibility rules

- Readers SHOULD tolerate unknown additive fields but MUST reject unsupported
  major schema versions.
- Required-field removal, meaning changes, or enum narrowing are breaking.
- Writers emit one declared version and do not produce ambiguous mixed formats.
- Adapters declare supported contract ranges and capabilities.
- The runtime validates compatibility before activation, not during the first
  risky effect.
- Lockfiles pin exact skills and adapters; ranges are resolved only during an
  explicit update.
- Deprecations include replacement guidance and remain supported for at least
  one documented compatibility window after a stable release.
- Storage upgrades require tested forward migration and a backup/restore or
  rollback path. Downgrade support is never implied.

## Maturity levels

### Level 0 — Architecture preview

Purpose: establish contracts, boundaries, threat model, and working scaffolds.

- No compatibility or security assurance.
- No production usage recommendation.
- APIs and formats may change freely with documentation.

Exit evidence:

- Approved core contracts and architecture decisions.
- Executable local scaffold and CI.
- Initial security model and evaluation plan.

### Level 1 — Developer preview

Purpose: demonstrate the complete local vertical slice.

- A reference engine works behind `ExecutionEngine`.
- A tool request is synchronously governed and evidenced.
- Embedded memory survives restart and requires evidence plus policy promotion.
- `init`, `doctor`, run inspection, and a safe replay path are usable.
- SkillLoop trace exchange is optional and contract-tested.

Compatibility is best effort and every unstable surface is marked.

### Level 2 — Alpha

Purpose: broaden adversarial coverage and validate replaceability.

- At least one second engine or a contract test double proves the engine
  boundary is provider-neutral.
- Embedded and hosted storage pass the same conformance suite.
- Policy bypass, approval binding, memory poisoning, prompt injection,
  contradiction, deletion, and scope leakage tests run in CI.
- Upgrade, backup/restore, cancellation, timeout, and partial failure paths are
  exercised.
- Signed or integrity-verified policies, skills, and adapters are supported.

No general production recommendation.

### Level 3 — Beta

Purpose: stabilize public integration surfaces and run controlled pilots.

- Public contracts have explicit compatibility windows.
- Supported platforms and versions run in CI.
- Security review, dependency review, release provenance, SBOM, and
  vulnerability process are operating.
- Hosted authentication, tenant isolation, secrets, retention, observability,
  and recovery have test evidence for pilot scope.
- Performance and reliability baselines are published with reproducible
  methodology; targets are based on those baselines.

### Level 4 — Stable OSS (`1.0`)

Purpose: support production use within published boundaries.

- Stable APIs, schemas, configuration, migration, and deprecation policy.
- Documented support and security-fix windows.
- Upgrade and rollback/restore rehearsals pass for supported versions.
- Release artifacts are reproducible to the documented level and include
  checksums, provenance, SBOM, and signatures where supported.
- Known limitations and unsupported capabilities are public.
- Operator and incident documentation is complete for the supported deployment
  modes.

### Level 5 — Enterprise supported

Purpose: provide contractual operations and integrations beyond stable OSS.

- Meets the readiness evidence described in `docs/ENTERPRISE_READINESS.md`.
- Support, availability, recovery, data handling, and compatibility commitments
  are explicit and scoped.
- Certifications or attestations are claimed only if formally obtained.

## Release train and channels

- `canary`: automated builds from the main integration branch; no compatibility
  promise and never the default install.
- `next`: release candidates for upcoming minor or major versions.
- `latest`: the current supported stable OSS release.
- Security fixes may use an embargoed patch branch and coordinated disclosure.

Cadence should follow readiness, not a fixed promise, until the project has
maintainer capacity and measured release lead time.

## Release gate

Every release candidate must provide:

1. Clean build from a tagged commit and locked dependencies.
2. Unit, integration, end-to-end, negative, adversarial, and conformance results
   required by its maturity level.
3. Migration and compatibility test results for supported upgrade paths.
4. Dependency and secret scans, SBOM, provenance, and artifact checksums.
5. Documentation command validation and accurate capability matrix.
6. Changelog entries grouped as security, breaking, added, changed, fixed,
   deprecated, and known limitations.
7. Human review of security-sensitive contract, policy, identity, isolation,
   storage, and release changes.
8. Rollback or restore decision and verified procedure.

Failures block promotion; waivers identify owner, scope, expiry, mitigation, and
user-visible impact.

## Release metrics

Track measured values without manufacturing targets:

- Candidate failure and rollback rates.
- Time from vulnerability report to supported-version remediation.
- Migration and restore exercise success.
- Contract compatibility failures found before release versus after release.
- Conformance pass rate by declared adapter capability.
- Documentation command drift.
- Escaped security- and data-integrity defects.

Targets are added only after a representative baseline and measurement process
exist.

## Support policy

Before stable OSS, only the latest release line is expected to receive fixes.
At `1.0`, the project publishes the number and duration of supported minor or
major lines, security severity handling, end-of-life notice, and backport rules.
No implied long-term support exists before it is explicitly published.
