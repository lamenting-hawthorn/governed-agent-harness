"""Dependency-free validator for the canonical Draft 2020-12 schema subset."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from importlib.resources import files
from importlib.resources.abc import Traversable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_bytes
from .errors import SchemaError

DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
_SUPPORTED_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "const",
        "description",
        "else",
        "enum",
        "format",
        "if",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "not",
        "oneOf",
        "pattern",
        "properties",
        "propertyNames",
        "required",
        "then",
        "title",
        "type",
        "uniqueItems",
    }
)


def _path(parent: str, child: str | int) -> str:
    escaped = str(child).replace("~", "~0").replace("/", "~1")
    return f"{parent}/{escaped}" if parent else f"/{escaped}"


def _fail(path: str, message: str) -> None:
    raise SchemaError(f"{path or '/'}: {message}")


def _json_equal(left: Any, right: Any) -> bool:
    try:
        return canonical_bytes(left) == canonical_bytes(right)
    except Exception:
        return False


def _matches_type(value: Any, expected: str) -> bool:
    return {
        "null": value is None,
        "boolean": isinstance(value, bool),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "string": isinstance(value, str),
        "array": isinstance(value, list),
        "object": isinstance(value, dict),
    }.get(expected, False)


def _validate_format(value: str, format_name: str, path: str) -> None:
    if format_name == "date-time":
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise SchemaError(f"{path or '/'}: invalid date-time") from exc
        if parsed.tzinfo is None:
            _fail(path, "date-time must include an offset")
        return
    if format_name == "uri":
        if any(ord(character) <= 0x20 for character in value):
            _fail(path, "URI contains whitespace or a control character")
        if re.search(r"%(?![0-9A-Fa-f]{2})", value):
            _fail(path, "URI contains malformed percent encoding")
        try:
            parsed = urlsplit(value)
            _ = parsed.port
        except ValueError as exc:
            raise SchemaError(f"{path or '/'}: invalid URI") from exc
        if not parsed.scheme or re.fullmatch(r"[A-Za-z][A-Za-z0-9+.-]*", parsed.scheme) is None:
            _fail(path, "URI must be absolute")
        return
    _fail(path, f"unsupported format {format_name!r}")


class SchemaStore:
    """Load and validate the immutable canonical v1 schema set."""

    def __init__(self, schema_directory: Path | Traversable | None = None) -> None:
        self.schema_directory = schema_directory or files(__package__).joinpath("schemas", "v1")
        self._documents: dict[str, dict[str, Any]] = {}
        self._catalog: dict[str, str] | None = None

    @property
    def catalog(self) -> Mapping[str, str]:
        if self._catalog is None:
            document = self._load_json("catalog.json")
            if document.get("schema_version") != "1.0":
                raise SchemaError("catalog.json: unsupported schema version")
            entries = document.get("contracts")
            if not isinstance(entries, list):
                raise SchemaError("catalog.json: contracts must be an array")
            catalog: dict[str, str] = {}
            for entry in entries:
                if not isinstance(entry, dict):
                    raise SchemaError("catalog.json: malformed contract entry")
                record_type, schema = entry.get("record_type"), entry.get("schema")
                if not isinstance(record_type, str) or not isinstance(schema, str):
                    raise SchemaError("catalog.json: malformed contract mapping")
                if record_type in catalog:
                    raise SchemaError(f"catalog.json: duplicate record_type {record_type!r}")
                catalog[record_type] = schema
            self._catalog = catalog
        return self._catalog

    def _load_json(self, name: str) -> dict[str, Any]:
        if name in self._documents:
            return self._documents[name]
        if Path(name).name != name:
            raise SchemaError(f"schema reference escapes canonical directory: {name!r}")
        path = self.schema_directory.joinpath(name)
        try:
            with path.open("r", encoding="utf-8") as handle:
                document = json.load(handle)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SchemaError(f"cannot load canonical schema {name!r}: {exc}") from exc
        if not isinstance(document, dict):
            raise SchemaError(f"canonical schema {name!r} is not an object")
        if name.endswith(".schema.json") and document.get("$schema") != DRAFT_2020_12:
            raise SchemaError(f"{name}: unsupported or missing JSON Schema dialect")
        self._documents[name] = document
        return document

    def schema_for(self, record_type: str) -> tuple[str, dict[str, Any]]:
        try:
            name = self.catalog[record_type]
        except KeyError as exc:
            raise SchemaError(f"unsupported record_type {record_type!r}") from exc
        return name, self._load_json(name)

    def audit_catalog(self) -> None:
        """Statically prove every canonical schema node uses the supported subset."""

        names = {"definitions.schema.json", *self.catalog.values()}
        for name in names:
            self._audit_schema_node(self._load_json(name), name, "#")

    def _audit_schema_node(self, schema: Any, schema_name: str, location: str) -> None:
        if isinstance(schema, bool):
            return
        if not isinstance(schema, dict):
            raise SchemaError(f"{schema_name}{location}: schema node must be an object or boolean")
        unknown = set(schema) - _SUPPORTED_KEYWORDS
        if unknown:
            raise SchemaError(
                f"{schema_name}{location}: unsupported schema keywords {sorted(unknown)!r}"
            )
        if "$ref" in schema:
            reference = schema["$ref"]
            if not isinstance(reference, str):
                raise SchemaError(f"{schema_name}{location}: $ref must be a string")
            self.resolve_ref(reference, schema_name)
        for keyword in (
            "additionalProperties",
            "not",
            "if",
            "then",
            "else",
            "items",
            "propertyNames",
        ):
            if keyword in schema and isinstance(schema[keyword], (dict, bool)):
                self._audit_schema_node(schema[keyword], schema_name, f"{location}/{keyword}")
        for keyword in ("allOf", "oneOf"):
            for index, subschema in enumerate(schema.get(keyword, [])):
                self._audit_schema_node(subschema, schema_name, f"{location}/{keyword}/{index}")
        for keyword in ("$defs", "properties"):
            for key, subschema in schema.get(keyword, {}).items():
                self._audit_schema_node(subschema, schema_name, f"{location}/{keyword}/{key}")

    def resolve_ref(self, reference: str, current_name: str) -> tuple[str, Any]:
        name, separator, fragment = reference.partition("#")
        target_name = name or current_name
        if "://" in target_name or target_name.startswith("urn:"):
            raise SchemaError(f"remote schema reference is forbidden: {reference!r}")
        document: Any = self._load_json(target_name)
        if separator and fragment:
            if not fragment.startswith("/"):
                raise SchemaError(f"unsupported schema fragment: {reference!r}")
            for token in fragment[1:].split("/"):
                token = token.replace("~1", "/").replace("~0", "~")
                if not isinstance(document, dict) or token not in document:
                    raise SchemaError(f"unresolved schema reference: {reference!r}")
                document = document[token]
        return target_name, document

    def validate_record(self, value: Any, record_type: str | None = None) -> None:
        if not isinstance(value, dict):
            _fail("", "record must be an object")
        version = value.get("schema_version")
        if not isinstance(version, str) or re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", version) is None:
            _fail("/schema_version", "version must be numeric dotted text")
        if version.split(".", 1)[0] != "1":
            _fail("/schema_version", f"unsupported major version {version!r}")
        actual_type = value.get("record_type")
        if not isinstance(actual_type, str):
            _fail("/record_type", "record_type must be a string")
        if record_type is not None and actual_type != record_type:
            _fail("/record_type", f"expected {record_type!r}, got {actual_type!r}")
        name, schema = self.schema_for(actual_type)
        self.validate(value, schema, name)

    def validate(
        self, value: Any, schema: Any, schema_name: str, path: str = "", depth: int = 0
    ) -> None:
        if depth > 128:
            _fail(path, "maximum schema validation depth exceeded")
        if isinstance(schema, bool):
            if not schema:
                _fail(path, "value is rejected by false schema")
            return
        if not isinstance(schema, dict):
            raise SchemaError(f"{schema_name}: schema node must be an object or boolean")

        unknown = set(schema) - _SUPPORTED_KEYWORDS
        if unknown:
            raise SchemaError(f"{schema_name}: unsupported schema keywords {sorted(unknown)!r}")

        if "$ref" in schema:
            reference = schema["$ref"]
            if not isinstance(reference, str):
                raise SchemaError(f"{schema_name}: $ref must be a string")
            target_name, target = self.resolve_ref(reference, schema_name)
            self.validate(value, target, target_name, path, depth + 1)

        for subschema in schema.get("allOf", []):
            self.validate(value, subschema, schema_name, path, depth + 1)

        if "oneOf" in schema:
            successes = 0
            for subschema in schema["oneOf"]:
                try:
                    self.validate(value, subschema, schema_name, path, depth + 1)
                except SchemaError:
                    continue
                successes += 1
            if successes != 1:
                _fail(path, f"oneOf matched {successes} schemas, expected exactly one")

        if "not" in schema:
            try:
                self.validate(value, schema["not"], schema_name, path, depth + 1)
            except SchemaError:
                pass
            else:
                _fail(path, "value matches a forbidden schema")

        if "if" in schema:
            try:
                self.validate(value, schema["if"], schema_name, path, depth + 1)
            except SchemaError:
                branch = schema.get("else")
            else:
                branch = schema.get("then")
            if branch is not None:
                self.validate(value, branch, schema_name, path, depth + 1)

        expected_type = schema.get("type")
        if expected_type is not None:
            expected_types = [expected_type] if isinstance(expected_type, str) else expected_type
            if not isinstance(expected_types, list) or not all(
                isinstance(item, str) for item in expected_types
            ):
                raise SchemaError(f"{schema_name}: malformed type keyword")
            if not any(_matches_type(value, item) for item in expected_types):
                _fail(path, f"expected type {expected_types!r}, got {type(value).__name__}")

        if "const" in schema and not _json_equal(value, schema["const"]):
            _fail(path, f"expected constant {schema['const']!r}")
        if "enum" in schema and not any(_json_equal(value, item) for item in schema["enum"]):
            _fail(path, f"value {value!r} is not in enum")

        if isinstance(value, str):
            if len(value) < schema.get("minLength", 0):
                _fail(path, "string is shorter than minLength")
            if len(value) > schema.get("maxLength", len(value)):
                _fail(path, "string is longer than maxLength")
            pattern = schema.get("pattern")
            if pattern is not None:
                try:
                    expression = re.compile(pattern)
                except re.error as exc:
                    raise SchemaError(
                        f"{schema_name}: invalid canonical regex {pattern!r}"
                    ) from exc
                match = (
                    expression.fullmatch(value)
                    if pattern.startswith("^") and pattern.endswith("$")
                    else expression.search(value)
                )
                if match is None:
                    _fail(path, f"string does not match pattern {pattern!r}")
            if "format" in schema:
                _validate_format(value, schema["format"], path)

        if isinstance(value, int) and not isinstance(value, bool):
            if value < schema.get("minimum", value):
                _fail(path, "integer is below minimum")
            if value > schema.get("maximum", value):
                _fail(path, "integer is above maximum")

        if isinstance(value, list):
            if len(value) < schema.get("minItems", 0):
                _fail(path, "array has fewer than minItems")
            if len(value) > schema.get("maxItems", len(value)):
                _fail(path, "array has more than maxItems")
            if schema.get("uniqueItems"):
                seen: set[bytes] = set()
                for index, item in enumerate(value):
                    frozen = canonical_bytes(item)
                    if frozen in seen:
                        _fail(_path(path, index), "array item is not unique")
                    seen.add(frozen)
            if "items" in schema:
                for index, item in enumerate(value):
                    self.validate(item, schema["items"], schema_name, _path(path, index), depth + 1)

        if isinstance(value, dict):
            if len(value) < schema.get("minProperties", 0):
                _fail(path, "object has fewer than minProperties")
            if len(value) > schema.get("maxProperties", len(value)):
                _fail(path, "object has more than maxProperties")
            required = schema.get("required", [])
            for key in required:
                if key not in value:
                    _fail(path, f"missing required property {key!r}")
            if "propertyNames" in schema:
                for key in value:
                    self.validate(
                        key, schema["propertyNames"], schema_name, _path(path, key), depth + 1
                    )
            properties = schema.get("properties", {})
            for key, subschema in properties.items():
                if key in value:
                    self.validate(value[key], subschema, schema_name, _path(path, key), depth + 1)
            extras = set(value) - set(properties)
            additional = schema.get("additionalProperties", True)
            if additional is False and extras:
                _fail(path, f"undeclared properties are forbidden: {sorted(extras)!r}")
            if isinstance(additional, dict):
                for key in extras:
                    self.validate(value[key], additional, schema_name, _path(path, key), depth + 1)


DEFAULT_SCHEMA_STORE = SchemaStore()
