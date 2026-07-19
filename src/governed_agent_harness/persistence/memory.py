"""Privileged-only PostgreSQL authority for evidence-backed memory promotion."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

from governed_agent_harness.contracts import (
    ConstraintRegistry,
    DetachedProofVerifier,
    TrustContext,
)

from .store import (
    MemoryPromotionAuthority,
    PostgresDurableEffectStore,
    StoredMemoryTransition,
)


class PostgresMemoryPromotionAuthority:
    """The only public Python promotion boundary.

    The constructor accepts one privileged authority connection factory.  A
    runtime connection is intentionally not accepted or retained; retrieval
    remains the separate actor-scoped read-only path on ``PostgresDurableEffectStore``.
    """

    def __init__(
        self,
        *,
        privileged_connect: Callable[[], Any],
        clock: Callable[[], datetime],
        ids: Callable[[], str],
        constraint_registry: ConstraintRegistry | None = None,
        approval_verifier: DetachedProofVerifier | None = None,
        approval_trust: Callable[[datetime], TrustContext] | None = None,
    ) -> None:
        self._authority = PostgresDurableEffectStore(
            connect=privileged_connect,
            privileged_connect=privileged_connect,
            clock=clock,
            ids=ids,
            constraint_registry=constraint_registry,
            approval_verifier=approval_verifier,
            approval_trust=approval_trust,
        )

    def promote_memory(
        self,
        *,
        actor_context: Mapping[str, Any],
        proposal: Mapping[str, Any],
        memory_decision: Mapping[str, Any],
        policy_decision: Mapping[str, Any],
        approvals: tuple[Mapping[str, Any], ...] = (),
        expected_revision: int | None = None,
    ) -> StoredMemoryTransition:
        return self._authority._promote_memory(
            actor_context=actor_context,
            proposal=proposal,
            memory_decision=memory_decision,
            policy_decision=policy_decision,
            approvals=approvals,
            expected_revision=expected_revision,
        )

    def rebuild_memory_projection(
        self, *, actor_context: Mapping[str, Any], memory_id: str
    ) -> StoredMemoryTransition:
        return self._authority._rebuild_memory_projection(
            actor_context=actor_context, memory_id=memory_id
        )


__all__ = [
    "MemoryPromotionAuthority",
    "PostgresMemoryPromotionAuthority",
    "StoredMemoryTransition",
]
