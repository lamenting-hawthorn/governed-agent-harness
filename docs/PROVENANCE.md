# Provenance and clean-room boundaries

This repository is an independent project with its own source, decisions, and
Git history. It does not share Git history with Governed Agent Architecture or
SkillLoop. Those projects remain optional external integration targets.

## Phase 0 contract foundation

The contract foundation was written for this repository from the approved
architecture requirements and is maintained under the
`governed_agent_harness.contracts` package. The canonical JSON schemas,
deterministic fixtures, validation rules, and runtime-state tests are project
artifacts owned by this repository.

## External systems

- Governed Agent Architecture is an optional interoperability target, not a
  code dependency or implementation base.
- SkillLoop is an optional offline evaluation and learning integration. It
  cannot directly mutate harness state.
- Execution engines remain behind versioned interfaces and the synchronous
  governance boundary.

No private materials, third-party source code, proprietary benchmarks, or
marketing claims are part of this repository. Future external code or assets
require an explicit license review and a project-owned attribution record before
acceptance.
