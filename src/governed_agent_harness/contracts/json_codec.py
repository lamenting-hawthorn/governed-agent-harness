"""Strict UTF-8 JSON wire decoding."""

from __future__ import annotations

import json
from typing import Any, NoReturn

from .canonical import canonical_bytes
from .errors import JsonDecodeError, SemanticError


def _reject_float(token: str) -> NoReturn:
    raise JsonDecodeError(f"floating-point token is forbidden: {token!r}")


def _reject_constant(token: str) -> NoReturn:
    raise JsonDecodeError(f"non-finite number token is forbidden: {token!r}")


def _object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise JsonDecodeError(f"duplicate object key is forbidden: {key!r}")
        result[key] = value
    return result


def strict_json_loads(payload: bytes | bytearray | memoryview) -> Any:
    """Decode one strict UTF-8 JSON value without numeric or Unicode repair."""

    if not isinstance(payload, (bytes, bytearray, memoryview)):
        raise TypeError("strict_json_loads requires bytes-like UTF-8 input")
    try:
        text = bytes(payload).decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise JsonDecodeError(f"invalid UTF-8 at byte {exc.start}") from exc
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except JsonDecodeError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise JsonDecodeError(f"invalid JSON: {exc}") from exc
    try:
        canonical_bytes(value)
    except (SemanticError, RecursionError) as exc:
        raise JsonDecodeError(str(exc)) from exc
    return value
