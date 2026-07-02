# Governed Agent Harness

Governed Agent Harness is a local-first foundation for building agents whose
actions, memory, skills, and learning inputs are controlled by explicit policy
and recorded as evidence.

The project is deliberately contract-first and runtime-neutral. It defines the
trust boundaries required for safe agent execution without coupling the
governance kernel to a model provider, transport, storage product, or learning
workflow.

## What it provides

- Versioned JSON Schema contracts for requests, decisions, evidence, memory,
  skills, approvals, and lifecycle records.
- Dependency-light Python validation and canonicalization utilities.
- Fail-closed policy and authorization boundaries for protected effects.
- Tenant- and actor-scoped durable state primitives.
- Tamper-evident evidence and explicit replay/idempotency semantics.
- Quarantined, reviewable learning imports that cannot mutate runtime state by
  themselves.
- Deterministic positive, negative, compatibility, and adversarial tests.

## Current status

The repository currently contains the contract foundation and the bounded Phase
1 governance kernel. It is suitable for architectural evaluation and continued
implementation work; it is not presented as a production-ready agent platform.
Runtime adapters, end-user CLI workflows, hosted operations, and deployment
hardening remain explicit release milestones.

See the [documentation index](docs/README.md), [contract catalog](contracts/v1/catalog.json),
[security model](docs/SECURITY_MODEL.md), and [release strategy](docs/RELEASE_STRATEGY.md).

## Quick start

Requires Python 3.11 or newer.

```console
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
pytest -q
ruff check .
```

The test suite is self-contained and does not require production credentials,
external services, or private infrastructure.

## Architecture

The core boundary is simple:

```text
caller or execution engine
            |
            v
  validated request -> policy -> approval -> authorized effect
            |              |          |
            +---------- evidence -----+
```

The governance kernel owns authorization, evidence, memory promotion, and
state transitions. Integrations remain outside the kernel and must use versioned
contracts. The [architecture guide](docs/ARCHITECTURE.md) describes the full
design and its invariants.

## Project relationship

This is an independent project authored and maintained in its own repository.
It may interoperate with [Governed Agent Architecture](docs/INTEGRATIONS.md)
and [SkillLoop](docs/EVALUATION_AND_LEARNING.md) through explicit, versioned
boundaries. Neither project is required to run the local contract foundation,
and neither can bypass this repository's governance controls.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Contracts](docs/CONTRACTS.md)
- [Security model](docs/SECURITY_MODEL.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Data governance](docs/DATA_GOVERNANCE.md)
- [Testing strategy](docs/TESTING_STRATEGY.md)
- [Contribution guide](CONTRIBUTING.md)
- [Governance](GOVERNANCE.md)
- [Security reporting](SECURITY.md)

## License

The project is released under the Apache License 2.0. See [LICENSE](LICENSE).
