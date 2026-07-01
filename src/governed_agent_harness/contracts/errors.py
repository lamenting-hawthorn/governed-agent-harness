"""Contract validation error types."""

from __future__ import annotations


class ContractError(ValueError):
    """Base class for fail-closed contract errors."""


class JsonDecodeError(ContractError):
    """Raised when wire JSON is not lexically safe."""


class SchemaError(ContractError):
    """Raised when a value does not satisfy its canonical JSON Schema."""


class SemanticError(ContractError):
    """Raised when a cross-field or cross-record invariant fails."""


class ProofVerificationError(SemanticError):
    """Raised when a signed proof or trust decision fails closed."""


class IdempotencyConflictError(SemanticError):
    """Raised when one idempotency key is rebound to a new operation."""
