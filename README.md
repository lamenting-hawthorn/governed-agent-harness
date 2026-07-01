# Governed Agent Harness

Governed Agent Harness is a new, standalone local-first agent harness with a
replaceable execution engine, enforceable policy gates, durable memory,
portable skills, tamper-evident run records, and controlled learning imports.

Phase 0 provides the canonical v1 wire contracts, a dependency-free Python
validation package, deterministic fixtures, and adversarial contract tests.
Runtime execution, persistence, adapters, and production services are not yet
implemented. See [the documentation index](docs/README.md) and
[contract catalog](contracts/v1/catalog.json).

## Repository Status

- Governed Agent Architecture remains an independent reference project.
- SkillLoop remains an independent evaluation and learning project.
- This repository owns the new execution harness and governance kernel.
- Existing systems are reached only through future versioned adapters; their
  implementation and Git history are not part of this repository.
- Pi is the first planned execution-engine adapter, not a fork or permanent
  architectural dependency.

See [provenance and clean-room boundaries](docs/PROVENANCE.md). No production
readiness or completed security posture is claimed.
