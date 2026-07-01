# Observability and Operations

## Objectives

Operations must make unsafe, failed, slow, and incomplete governance visible
without turning telemetry into a data-leak channel. Telemetry is diagnostic;
the evidence ledger is the authoritative record of governed events.

The implementation should use OpenTelemetry-compatible traces, metrics, and
structured logs. Vendor-specific exporters remain optional adapters.

## Correlation model

Every request receives non-secret identifiers for request, trace, run, turn,
tenant, actor (pseudonymous where appropriate), engine, policy version, tool,
approval, ledger event, and deployment version. Context propagates across
process, queue, provider, and adapter boundaries. Missing propagation is a
contract failure, not silently replaced with unrelated traces.

## Traces

Expected spans include:

- ingress authentication and authorization;
- run and turn coordination;
- model call with provider/model and bounded usage metadata;
- memory query, scope filter, ranking, and promotion;
- normalized effect request and policy evaluation;
- approval wait and decision;
- broker dispatch and sandbox execution;
- evidence append and integrity checkpoint;
- adapter export/import; and
- migration, backup, restore, and deletion jobs.

Span attributes never include secret values, full prompts, unrestricted tool
arguments, or raw tool output by default. Content capture is a separately
authorized, time-bounded diagnostic mode with visible warnings and redaction.

## Metrics

Core metrics include:

- run/turn success, cancellation, timeout, and error by stable reason code;
- policy decisions by action, risk, decision, and policy version;
- effects attempted, denied, approved, executed, failed, and bypass-detection
  alerts;
- approval queue depth, age, expiry, and consumption conflicts;
- model latency, token usage, retry count, and budget exhaustion;
- sandbox startup, execution, timeout, resource limit, and cleanup failures;
- ledger append latency/failure, sequence gaps, and integrity-check status;
- memory proposals, promotion/rejection, retrieval use, conflicts, expiry, and
  deletion backlog;
- queue depth, retry age, dead letters, and dropped telemetry;
- adapter contract failures and capability mismatches; and
- backup age, restore-test age, migration state, and readiness.

Metric labels are bounded. Never use prompts, paths, arbitrary tool arguments,
user email, raw tenant name, or unbounded error messages as labels.

## Logs

Logs are structured, timestamped, severity-classified, and contain stable event
and error codes. Expected errors are not logged with full stack traces. Security
events record actor/tenant pseudonymous IDs, resource, policy, decision, reason,
and correlation IDs without sensitive payloads. Redaction runs before emission
to every sink, including console output.

## Initial service objectives

Numeric targets are adopted only after representative baseline measurement.
Until then, releases define and measure indicators without claiming an SLO.
Before hosted production, owners must approve targets for:

- availability of governed request handling;
- latency of policy decisions and evidence appends;
- percentage of covered effects evaluated before execution;
- evidence completeness and integrity verification;
- approval processing latency;
- recovery point and recovery time objectives;
- deletion completion time; and
- maximum age of successful backup and restore verification.

The policy-before-effect coverage target for declared Gate/Isolate capabilities
is 100%; any known bypass is a correctness/security defect, not an error-budget
tradeoff.

## Health and readiness

Liveness reports only that the process can make progress. Readiness verifies
required configuration, identity keys, policy bundle, ledger/storage access,
migration compatibility, broker availability, and mandatory queues. Optional
providers are reported individually as available, degraded, or disabled.

The `doctor` command performs non-destructive checks and reports versions,
capabilities, missing configuration, storage/migration status, sandbox support,
provider reachability, clock skew, and redaction configuration. It must not
print secrets.

An unavailable policy engine, invalid policy bundle, or unavailable mandatory
ledger makes effect handling unready. A failed remote telemetry exporter does
not block effects if authoritative evidence is durable and the retry queue has
capacity; it does mark telemetry degraded.

## Alerting and runbooks

Alerts must be actionable, owned, deduplicated, and linked to a runbook.
Release-blocking runbooks cover:

- policy or identity service failure;
- suspected tool-policy bypass;
- cross-tenant access signal;
- secret/PII leak signal;
- ledger integrity failure or sequence gap;
- sandbox escape indicator or cleanup failure;
- approval replay/conflict;
- provider outage and retry storm;
- storage exhaustion or migration failure;
- backup failure and restore failure; and
- deletion backlog breach.

Runbooks state detection, immediate containment, evidence preservation,
communications owner, rollback/failover, recovery validation, and follow-up.

## Backups and recovery

Backups are encrypted, access-controlled, versioned, monitored, and separated
from primary credentials. The backup design records covered datasets, schedule,
retention, region/location, RPO, RTO, and key recovery dependency. A backup is
not considered valid until an automated restore into an isolated environment
passes schema, integrity, tenant-isolation, tombstone, and sampled data checks.

Restore procedures must reapply deletion tombstones before restored data can be
served. Restore exercises occur on a defined schedule and after material schema
or storage changes.

## Migrations

Persisted schemas and public event contracts are versioned. Migrations are
forward-tested on production-like scale, idempotent where feasible, observable,
and have documented compatibility windows. Destructive transformations require
backup verification, staged rollout, explicit approval, and a recovery plan.

Deployments use expand/migrate/contract for incompatible changes:

1. Add backward-compatible schema and dual-read/write only when necessary.
2. Backfill with bounded, restartable jobs and progress metrics.
3. Verify invariants and consumers.
4. Switch reads and observe.
5. Remove old structures in a later release.

## Incident response

Incidents receive severity, incident commander, timeline, affected scope, and
preserved evidence. Credentials are rotated through approved mechanisms; raw
secrets are never pasted into tickets or chat. Customer/security notification
requirements are deployment-specific and documented before production.
Post-incident reviews are blameless, identify control and detection gaps, assign
owners and dates, and add regression tests when technically possible.
