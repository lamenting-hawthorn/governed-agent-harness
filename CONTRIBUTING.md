# Contributing

Thank you for helping build Governed Agent Harness. The project is intended to
be Apache-2.0 licensed. By submitting a contribution, you agree that it may be
licensed under the Apache License 2.0 when the project license is added. Do not
contribute code or content you do not have the right to submit.

## Before contributing

- Read `AGENTS.md`, the architecture documentation, `SECURITY.md`, and relevant
  architecture decision records.
- Open an issue or discussion before large API, storage, security-boundary, or
  dependency changes.
- Report vulnerabilities privately according to `SECURITY.md`.
- Never include credentials, customer data, proprietary code, private traces,
  or copied implementations from reference projects.

## Development principles

- Keep the execution engine replaceable; Pi stays behind its adapter boundary.
- Treat model output, skills, memory candidates, and external content as
  untrusted.
- Route protected effects through synchronous policy evaluation.
- Require source evidence and policy disposition for memory promotion.
- Keep learning proposals reviewable and versioned; no automatic live mutation.
- Preserve local/hosted semantic parity and version public/persisted contracts.
- Prefer small, explicit changes over broad refactors.
- Document implemented behavior and limitations without overstating security.

## Workflow

1. Branch from current main and keep one coherent concern per change.
2. Add or update an ADR for material, hard-to-reverse architectural decisions.
3. Implement the smallest complete change with tests and documentation.
4. Run the repository's documented formatting, lint, type, test, link, secret,
   and dependency checks. Until tooling is scaffolded, at minimum run
   `git diff --check` and verify Markdown links manually.
5. Review the diff for unrelated files, generated output, secrets, and private
   data.
6. Open a pull request using a clear problem statement and evidence.

Do not rewrite shared history, force-push over another contributor's work, or
commit local databases, environment files, caches, build output, or credentials.

## Pull request requirements

A pull request should include:

- problem, scope, and explicit non-goals;
- design and alternatives for non-trivial changes;
- affected trust boundaries, effect classes, contracts, migrations, and data;
- tests run with exact results and any intentionally skipped coverage;
- screenshots or user-facing evidence when applicable;
- rollout, compatibility, and rollback notes; and
- documentation and ADR updates.

Security-relevant changes require negative-path and adversarial tests. Adapter
changes require the shared conformance suite. Persisted-schema changes require
migration and recovery tests. Claims such as “secure,” “isolated,” or “tenant
safe” require linked evidence and stated limits.

## Review

At least one maintainer approval is required. Changes to authentication,
authorization, policy-before-effect, sandboxing, secrets, tenant isolation,
memory trust, evidence integrity, release automation, or dependency execution
require an independent security-minded reviewer who did not author the change.

Reviewers verify correctness, scope, failure behavior, compatibility,
maintainability, test quality, observability, and documentation. Approval does
not transfer responsibility away from the author or maintainer.

## Tests and fixtures

Tests must be deterministic by default and must not require production secrets
or external services. Use synthetic tenants, data, and canary credentials.
Live-provider tests are opt-in and budget-bounded. A skipped release-blocking
test must fail CI or have a documented, expiring quarantine with an owner.

## Commits and provenance

Write focused commits with imperative messages. Preserve authorship and third-
party notices. If an AI tool materially assists a contribution, the contributor
remains responsible for licensing, security, correctness, tests, and review.
Do not submit generated code you cannot explain and maintain.

## Community conduct and governance

Participation is governed by `CODE_OF_CONDUCT.md`; project decision-making is
described in `GOVERNANCE.md`. By participating, you agree to those policies.
