"""RFC 8785 canonical JSON for the contracts' integer-only domain."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from .errors import SemanticError

MAX_SAFE_INTEGER = 9_007_199_254_740_991


def _validate_unicode(value: str, path: str) -> None:
    for character in value:
        codepoint = ord(character)
        if 0xD800 <= codepoint <= 0xDFFF:
            raise SemanticError(f"{path}: Unicode surrogate is forbidden")
        if codepoint == 0xFFFD:
            raise SemanticError(f"{path}: Unicode replacement character is forbidden")


def _utf16_sort_key(value: str) -> bytes:
    _validate_unicode(value, "object key")
    return value.encode("utf-16-be")


def _string_bytes(value: str, path: str) -> bytes:
    _validate_unicode(value, path)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _canonicalize(value: Any, path: str, depth: int = 0) -> bytes:
    if depth > 128:
        raise SemanticError(f"{path or '/'}: maximum canonicalization depth exceeded")
    if value is None:
        return b"null"
    if value is True:
        return b"true"
    if value is False:
        return b"false"
    if isinstance(value, int):
        if not -MAX_SAFE_INTEGER <= value <= MAX_SAFE_INTEGER:
            raise SemanticError(f"{path}: integer is outside the interoperable safe range")
        return str(value).encode("ascii")
    if isinstance(value, float):
        raise SemanticError(f"{path}: floating-point values are unsupported")
    if isinstance(value, str):
        return _string_bytes(value, path)
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise SemanticError(f"{path}: object keys must be strings")
        parts: list[bytes] = []
        for key in sorted(value, key=_utf16_sort_key):
            child_path = f"{path}/{key}" if path else f"/{key}"
            parts.append(
                _string_bytes(key, child_path)
                + b":"
                + _canonicalize(value[key], child_path, depth + 1)
            )
        return b"{" + b",".join(parts) + b"}"
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray, str)):
        return (
            b"["
            + b",".join(
                _canonicalize(item, f"{path}/{index}", depth + 1)
                for index, item in enumerate(value)
            )
            + b"]"
        )
    raise SemanticError(f"{path or '/'}: unsupported JSON value {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return RFC 8785 bytes for JSON values in the supported integer domain."""

    return _canonicalize(value, "")


def sha256_digest(value: Any) -> str:
    """Return the canonical SHA-256 digest for a JSON value."""

    return sha256_bytes(canonical_bytes(value))


def sha256_bytes(value: bytes) -> str:
    """Return a lowercase prefixed SHA-256 digest for bytes."""

    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def is_sha256_digest(value: object) -> bool:
    """Return whether *value* is a canonical prefixed SHA-256 string."""

    if not isinstance(value, str) or len(value) != 71 or not value.startswith("sha256:"):
        return False
    suffix = value[7:]
    return all(character in "0123456789abcdef" for character in suffix)


def require_sha256_digest(value: object, path: str = "digest") -> str:
    """Return a valid digest or fail closed."""

    if not is_sha256_digest(value):
        raise SemanticError(f"{path}: expected sha256:<64 lowercase hex>")
    return value
