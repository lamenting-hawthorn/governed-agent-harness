# AGENTS.md

## Mission

Build a runtime-neutral governed agent harness whose actions, memory, skills,
and learning are evidence-backed, policy-controlled, and auditable.

## Non-negotiable boundaries

- Do not edit Governed Agent Architecture or SkillLoop from this repository.
- Do not copy large implementations from Pi, GBrain, ECC, GCG, SkillLoop, or
  Governed Agent Architecture. Reuse contracts and ideas with attribution.
- Pi must remain behind the `ExecutionEngine` boundary.
- MCP is an integration transport, not the complete governance boundary.
- Tool execution must never bypass synchronous policy evaluation.
- Memory must never be promoted without source evidence and a policy decision.
- Learning artifacts must never mutate the live runtime automatically.
- Never expose secrets, tokens, credentials, private traces, or user data.
- Never claim a security property without a test that demonstrates it.

## Worktree and agent rules

- Every implementation agent works in its own Git worktree and branch.
- Each agent receives an explicit file ownership list and forbidden paths.
- Agents may not edit files owned by another active workstream.
- Shared contracts are modified only by the contracts owner or through a
  reviewed integration commit.
- Every workstream must commit coherent changes before handoff.
- The integration owner merges workstreams one at a time and runs the full gate
  after every merge.
- Unrelated user changes must be preserved.

## Engineering standards

- Contract-first, explicit, and boring over clever.
- Local-first behavior and hosted behavior must share the same semantics.
- Validate inputs at boundaries and effects at sinks.
- Prefer append-only evidence and explicit supersession over destructive edits.
- All public APIs and persisted schemas are versioned.
- New behavior requires unit, integration, negative-path, and adversarial tests
  proportional to risk.
- Documentation must describe current behavior, not planned behavior, once code
  begins shipping.

## Validation

The implementation plan defines the final commands. Until scaffolding exists,
documentation changes must at minimum pass Markdown link checks, formatting
checks, and `git diff --check`.

