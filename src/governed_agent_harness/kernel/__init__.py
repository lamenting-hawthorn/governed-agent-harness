"""In-process, fail-closed governance and governed-effects kernel."""

from .core import (
    GovernanceKernel,
    IdentityVerifier,
    IdentityError,
    InMemoryEvidenceLedger,
    KernelLifecycle,
    LifecycleError,
    PolicyConfigurationError,
    PolicyRule,
    PolicySet,
)
from .effects import (
    AuthorizationGrantIssuer,
    EffectConfigurationError,
    EffectExecutor,
    ExecutorCapabilities,
)

__all__ = [
    "GovernanceKernel",
    "AuthorizationGrantIssuer",
    "EffectConfigurationError",
    "EffectExecutor",
    "ExecutorCapabilities",
    "IdentityVerifier",
    "IdentityError",
    "InMemoryEvidenceLedger",
    "KernelLifecycle",
    "LifecycleError",
    "PolicyConfigurationError",
    "PolicyRule",
    "PolicySet",
]
