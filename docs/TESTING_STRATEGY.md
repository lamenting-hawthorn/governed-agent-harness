# Testing Strategy

## Purpose

Tests provide evidence for behavior and security claims. The suite must prove
that protected effects cannot occur through expected and adversarial paths,
that data scope is preserved, and that persisted evidence and memory remain
correct across failure, restart, migration, and concurrency.

## Test layers

| Layer | Required coverage |
| --- | --- |
| Unit | Pure policy rules, normalization, schemas, redaction, hashing, budgets, path/network validation, memory lifecycle |
| Contract | Every execution engine, tool, memory/knowledge provider, sandbox, ledger, SkillLoop export, and protocol adapter |
| Integration | Kernel plus real storage/broker/provider boundaries; failure and retry semantics |
| End-to-end | Install, init, run, gated tool, approval, restart, memory retrieval, evidence inspection, export |
| Adversarial | Injection, poisoning, bypass, tenant escape, secret leakage, replay, supply-chain, deletion resurrection |
| Fuzz/property | Parsers, schema boundaries, event ordering, path/URL handling, policy normalization, migration invariants |
| Performance/reliability | Load, soak, resource budgets, queue pressure, cancellation, crash recovery, large histories |
| Operational | Backup/restore, migrations, key rotation, dependency/provider outage, runbooks, alerts |

## Unit expectations

Unit tests are deterministic, isolated from network and clock, and include
positive, negative, boundary, and error cases. Policy tests use table-driven
fixtures and verify stable reason codes. Security validators use known bypass
corpora. Snapshot tests may support review but cannot be the sole assertion for
authorization or policy behavior.

## Contract conformance

A shared conformance kit runs against every implementation of a public
contract. It validates schema versions, capability manifests, cancellation,
timeouts, idempotency, error mapping, correlation propagation, redaction, and
unsupported-capability behavior.

Execution-engine conformance additionally proves:

- all declared tool/effect requests traverse the synchronous gate;
- the engine cannot receive raw effect capabilities outside the broker;
- request mutation invalidates a decision;
- Observe and Advise are never reported as preventive enforcement; and
- events preserve ordering and provenance across retries.

Storage-provider conformance proves tenant filtering before ranking, revision
and tombstone behavior, transaction boundaries, concurrent writes, restart
durability, and migration compatibility.

The PostgreSQL Phase 4 hardening gate additionally runs against a real server
and proves migration lock/checksum/drift behavior, exact legacy adoption,
owner/runtime/authority role privileges, forced RLS, denied direct DML,
denied runtime transition calls, and migration
tampering, lifecycle replay/projection rebuild, restart at every pre-effect
state, lease renewal/expiry, stale-owner rejection, and concurrent
completion-versus-recovery fencing. In-memory or SQLite substitutes do not
satisfy this gate.

The in-progress governed-memory retrieval slice additionally proves on that
real server that the runtime role cannot read or write memory tables directly,
cannot forge a tenant or actor through the retrieval function, and receives
only deterministic active latest revisions within its exact actor scope. Tests
cover revision tombstones, temporal bounds, restart-equivalent reads, and
rejected project-scoped queries. There is no automatic memory-promotion path.

## End-to-end reference story

The release E2E test starts from a clean machine/container and must:

1. Install using documented commands without external infrastructure.
2. Initialize local identity, policy, storage, and a reference engine adapter.
3. Run a request that proposes a harmless tool call.
4. Demonstrate allow, deny, and approval decisions.
5. Execute only the normalized approved request in its declared boundary.
6. Inspect the linked request, policy, approval, outcome, and integrity record.
7. Propose memory with evidence, reject one candidate, and promote another.
8. Restart and retrieve the approved memory without retrieving rejected or
   cross-scope data.
9. Export a versioned SkillLoop-compatible trace and validate its schema.
10. Run `doctor` and receive an accurate healthy/degraded report.

## Mandatory adversarial suites

- Direct and indirect prompt injection, including instructions in retrieved
  documents, tool output, filenames, and memory.
- Memory poisoning, conflict, forged provenance, stale authority, oversized
  evidence, and cross-tenant candidates.
- Tool bypass through engine extensions, direct imports, nested tools, retries,
  alternate transports, and cancellation races.
- Approval replay, expiry, double consumption, argument/identity mutation, and
  time-of-check/time-of-use races.
- Filesystem traversal, symlink races, command injection, SSRF, redirects, DNS
  rebinding, IPv4/IPv6 variants, metadata services, and output flooding.
- Secret and PII leakage through prompts, errors, logs, traces, metrics, child
  processes, exports, and redaction edge cases.
- Tenant escape through IDs, caches, queues, search, backups, exports, and
  administrative endpoints.
- Malicious skills, invalid signatures/hashes, dependency confusion, permission
  escalation, incompatible upgrades, and rollback.
- Learning artifacts that attempt automatic policy, skill, or memory mutation.
- Deletion followed by restart, index rebuild, restore, replay, and reimport.

Fixtures use synthetic canary secrets and tenants. Tests never use production
credentials or customer data.

## Fuzzing and property tests

Fuzz untrusted parsers and normalization boundaries continuously in CI within a
bounded budget and in longer scheduled jobs. Important properties include:

- normalization is deterministic and stable for a schema version;
- decisions bind exactly to normalized requests;
- authorization never broadens scope;
- event sequence and hash linkage detect removal, reorder, and mutation;
- redaction never returns a known canary secret;
- supersession and deletion never resurrect inactive memory; and
- retries do not duplicate externally visible effects.

Crashes produce minimized regression fixtures.

## Test environments and dependencies

The default suite runs offline with deterministic fake model and provider
implementations. Integration jobs exercise supported real databases, operating
systems, runtimes, and sandbox backends. Live-provider tests are opt-in,
credential-safe, budget-capped, and are not required to reproduce core policy
correctness. Model-quality evaluations report variance and dataset versions.

## CI gates

Every change must pass formatting, lint, type checking, unit tests, contract
tests for affected adapters, dependency/secret scans, and changed-file policy.
Risk-relevant changes also run integration, adversarial, and E2E suites. Main
and release candidates run the complete supported matrix, migration tests,
artifact/SBOM generation, and reproducibility checks.

Tests must fail on skipped mandatory coverage, unexpected network access,
unhandled promise/rejection, leaked handles, and secret canary appearance.
Flaky tests are defects: quarantine requires an owner, issue, expiry, and no
coverage loss for a release-blocking invariant.

## Coverage and traceability

Line coverage is a diagnostic, not the quality target. Each invariant, threat,
public contract, and acceptance criterion maps to named tests. Release notes
identify verified platforms and limitations. A security claim without linked
negative-path evidence does not ship.

## Manual and independent review

Automated tests do not replace threat review, architecture review, usability
testing, or an independent security assessment for high-risk enterprise use.
Before a stable release, a reviewer who did not implement the change exercises
the install/run/approval/recovery story and challenges the relevant invariants.
