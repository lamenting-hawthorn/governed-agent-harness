# Provenance and clean-room boundaries

This repository was initialized as a new standalone project. It does not share
Git history with Governed Agent Architecture, SkillLoop, or any reference
project. Those systems remain external integration targets.

## Phase 0 contract foundation

The Phase 0 contracts were independently written from the approved local
architecture requirements and first reviewed at source snapshot
`540ef9816a68cecad54def8a624f1c69601a3327`. The reviewed files were transferred
as a clean snapshot into this repository and re-homed under the
`governed_agent_harness.contracts` package. No source repository commits or
runtime implementation were imported.

The canonical JSON schemas and deterministic fixtures are byte-equivalent to
that reviewed snapshot. Python changes are limited to the new package identity,
standalone path resolution, packaging metadata, and isolation assertions.

## External systems

- Governed Agent Architecture is a runtime interoperability target, not a code
  dependency or implementation base.
- SkillLoop is the external offline evaluation and learning plane. It cannot
  directly mutate harness state.
- Execution engines, including a future Pi adapter, remain behind versioned
  interfaces and the synchronous governance boundary.

Other than the independently written Phase 0 contract snapshot identified
above, no external source code, private materials, third-party schemas,
diagrams, assets, proprietary benchmarks, or marketing claims were introduced.
Future third-party code or assets require explicit license and attribution
records before acceptance.
