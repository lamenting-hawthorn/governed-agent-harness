# Project Governance

## Principles

Governed Agent Harness is developed in the open with technical decisions based
on user safety, evidence, maintainability, interoperability, and long-term
project health. Authority carries responsibility for review, incident response,
release quality, and community conduct.

This document describes the initial maintainer-led model. It must be updated as
the contributor community grows; it does not imply a foundation or elected body
that does not yet exist.

## Roles

### Contributors

Anyone who participates through issues, documentation, code, design, testing,
security reports, or community support. Contributors follow the contribution
guide and Code of Conduct.

### Reviewers

Trusted contributors with demonstrated expertise in an area. Reviewers assess
changes but cannot merge solely by virtue of the role. Security-sensitive
changes require an independent reviewer who did not author the work.

### Maintainers

Maintainers triage work, approve and merge changes, manage releases and access,
coordinate vulnerabilities and incidents, enforce conduct, and steward the
architecture. The repository's GitHub permissions are the authoritative current
maintainer roster until a public list is added.

Maintainers use least privilege, strong authentication, protected branches, and
reviewable automation. No individual should approve their own high-risk change
or unilaterally publish a stable release once the project has enough maintainers
to separate those duties.

## Decisions

Routine, reversible changes use pull-request consensus: address substantive
review concerns and obtain required approval. Material decisions use an ADR,
including public contracts, storage semantics, enforcement tiers, identity,
policy, sandbox boundaries, memory trust, evidence integrity, supported
platforms, and major dependencies.

ADRs state context, decision, alternatives, consequences, security impact, and
status. Maintainers seek rough consensus. If consensus cannot be reached, the
designated repository lead decides and records the reasoning. Decisions can be
revisited with new evidence through a superseding ADR.

## Change control

- Protected branches require CI and review.
- Security-boundary and release-workflow changes require two-person review when
  maintainer capacity permits; until then, they remain experimental and receive
  explicit independent review before stable release.
- Breaking changes follow the documented versioning and deprecation policy.
- Persisted data changes include migrations, recovery, and compatibility tests.
- Emergency changes are narrowly scoped, recorded, tested as soon as possible,
  and reviewed retrospectively.

## Releases

Maintainers publish versioned artifacts from protected, reproducible automation.
A release owner verifies the Definition of Done, dependency lock, tests,
migrations, documentation, SBOM/provenance, checksums, and known limitations.
Stable releases cannot be based solely on one person's local build.

## Security and conduct

Vulnerabilities follow `SECURITY.md`; behavior follows `CODE_OF_CONDUCT.md`.
People handling private reports disclose conflicts of interest, limit access to
those who need it, preserve confidentiality, and recuse themselves when needed.

## Becoming or removing a maintainer

Maintainer candidates demonstrate sustained, high-quality contributions, sound
judgment across trust boundaries, respectful collaboration, reliable review,
and willingness to support releases and incidents. Existing maintainers approve
appointments and document them publicly when a roster exists.

Maintainers may step down at any time. Access may be suspended for inactivity,
credential risk, repeated policy violations, or Code of Conduct enforcement.
Removal decisions are documented to the extent compatible with privacy and
security.

## Project assets and succession

Domains, package namespaces, signing keys, CI credentials, and organization
access are project assets. They must use recoverable organization-controlled
accounts rather than an individual's only copy. Before the first stable release,
the project will document ownership, backup contacts, and succession procedures.
