# Enterprise Readiness

## Purpose

The project is OSS-first and local-first. Enterprise capability is designed
into contracts and trust boundaries early, then delivered through measurable
maturity gates. This document is not a claim of compliance, certification, or
production suitability.

An enterprise deployment is ready only for the controls it has implemented,
tested, operated, and independently reviewed in its own environment.

## Deployment model

The open-source kernel remains the source of truth for policy semantics,
evidence, memory lifecycle, adapter contracts, and conformance. Enterprise
deployments may add managed services and commercial integrations around those
contracts, including centralized identity, policy distribution, managed
isolation, audit export, and administration.

Local and hosted modes must not assign different meanings to allow, deny,
approval, evidence, memory scope, or artifact installation. Infrastructure can
differ; contract semantics cannot silently diverge.

## Readiness domains

### Identity and access management

Required capabilities:

- OIDC/SAML-derived authenticated actor and organization identity.
- Tenant, project, role, and service-principal scope carried through every
  request, decision, evidence record, and storage operation.
- Role- and attribute-based authorization for operations and data.
- Short-lived service credentials and workload identity where supported.
- Step-up authentication for high-risk approvals.
- Separation of policy author, approver, operator, auditor, and runtime roles.
- Immediate session and credential revocation with evidenced outcomes.

Caller-provided tenant identifiers are never sufficient proof of membership.

### Tenant and data isolation

- Tenant scope is mandatory on every persisted object and query path.
- Application authorization and database enforcement provide independent
  boundaries; privileged service roles are narrowly scoped and monitored.
- Cross-tenant negative tests run against APIs, jobs, exports, caches, search,
  backups, and administrative operations.
- Encryption in transit and at rest is configured with documented ownership and
  rotation responsibilities.
- Regional placement and data-residency constraints are explicit capabilities.
- Local development fixtures cannot contain production tenant data.

### Policy lifecycle and approvals

- Policy artifacts are versioned, integrity-verified, reviewable, and
  attributable to an authenticated author.
- Promotion between environments requires defined review and change control.
- Approval binds to the immutable digest of the proposed effect.
- Delegation, expiry, revocation, quorum, break-glass, and separation-of-duty
  behavior are documented and tested.
- Break-glass access is time-bound, strongly authenticated, narrowly scoped,
  alerted, and fully audited.
- Runtime behavior on policy-service timeout or partition is deterministic and
  defaults to no unapproved effect.

### Secrets and external systems

- Enterprise secret providers expose references or short-lived credentials,
  not raw values to logs or evidence.
- Tool permissions use least-privilege identities per tenant and environment.
- Egress destinations, methods, and credential use are policy-controlled.
- External effects use idempotency and reconciliation when the target permits.
- Connectors document data transmitted, permissions requested, retention, and
  revocation behavior.

### Audit, privacy, and records

- Evidence is append-only, correlated, integrity-protected, and exportable to
  customer-controlled systems.
- Audit access is separately authorized and all audit reads are themselves
  auditable.
- Redaction, retention, legal hold, deletion, and subject-access workflows are
  explicit operations with proof of completion or exceptions.
- Exports record schema, policy, redactions, omissions, time range, and signer.
- Sensitive content is minimized; operational telemetry does not become an
  uncontrolled copy of prompts, secrets, or customer data.

### Reliability and continuity

- Availability objectives are defined per service and dependency after
  production baselines exist.
- Backups are encrypted, tenant-aware, restored regularly, and covered by
  documented recovery objectives.
- Migrations are staged, observable, and reversible or paired with a tested
  restore procedure.
- Queue replay, retry, timeout, and partial-failure semantics preserve effect
  and evidence truth.
- Regional or service degradation cannot silently disable policy enforcement.
- Capacity, rate limits, quotas, and backpressure protect tenants from noisy
  neighbors.

### Observability and incident response

- Metrics, logs, and traces correlate by tenant-safe run and decision IDs.
- Restricted content is excluded or redacted before telemetry export.
- Alerts cover policy bypass attempts, isolation failure, unusual approval use,
  tenant boundary denial, evidence write failure, and secret-provider errors.
- Incident runbooks define containment, credential rotation, evidence
  preservation, tenant notification inputs, and recovery verification.
- A sanitized diagnostic bundle is available without unrestricted data export.

### Supply chain and release controls

- Dependencies are pinned or locked, scanned, and reviewed according to risk.
- Builds are reproducible to the practical extent documented by the project.
- Artifacts include SBOM, provenance, checksums, and signatures when supported.
- Release permissions use least privilege and protected environments.
- Adapters and skills carry integrity identity, provenance, compatibility, and
  permissions; loading never implies trust.
- Vulnerability reporting, triage, embargo, remediation, and supported-version
  policies are public.

## Control evidence matrix

Before an enterprise claim is made, the release should link each claim to
evidence such as:

| Control | Minimum evidence |
| --- | --- |
| Tenant isolation | Cross-tenant API and direct-storage negative tests plus architecture review |
| No tool bypass | Engine conformance and adversarial dispatcher tests |
| Approval binding | Mutation, replay, expiry, and concurrency tests against request digests |
| Memory provenance | Rejection tests for missing evidence and end-to-end revision tests |
| Secret safety | Log/evidence scanning and seeded secret canary tests |
| Recovery | Recorded backup restore and migration failure exercise |
| Artifact integrity | Verification tests for tampered skills, policies, and releases |
| Audit completeness | Causal trace tests across decision, effect, failure, and retry paths |

The detailed threat model is expected in `docs/SECURITY_MODEL.md`; evaluation
methodology is expected in `docs/TESTING_AND_EVALUATION.md`.

## Enterprise capability phases

### Foundation

- Contract-level tenant and actor scope.
- Local evidence and policy semantics.
- Provider boundaries and conformance suites.
- No enterprise availability or compliance claim.

### Controlled pilot

- Authenticated hosted deployment.
- Tested tenant isolation, centralized policy, managed secrets, audit export,
  backup/restore, monitoring, and incident runbooks.
- Limited environments, workloads, and support commitments are explicit.

### Production candidate

- Completed security review and threat remediation.
- Load, failure, disaster recovery, upgrade, rollback, and isolation exercises.
- Defined objectives, support policy, data handling, subprocessor inventory,
  vulnerability process, and operational ownership.
- Independent assessment for claims the project intends to make.

### Enterprise supported

- Published support and compatibility windows.
- Continuous control evidence, regular recovery exercises, release provenance,
  incident response program, and customer-facing operational documentation.
- Compliance attestations only where formally obtained and within their stated
  scope.

## Explicit non-claims

Architecture alone does not make the product SOC 2, ISO 27001, HIPAA, GDPR, or
any other compliance standard compliant. Encryption alone does not establish
tenant isolation. An append-only application table alone is not immutable
audit. MCP integration alone does not govern tools executed by its host.

These statements remain true even when the project later offers enterprise
packaging.
