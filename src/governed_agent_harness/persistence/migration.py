"""Fail-closed discovery and installation of immutable PostgreSQL migrations."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Protocol


_MIGRATION_NAME = re.compile(r"^(?P<version>[0-9]{4})_[a-z0-9_]+\.sql$")
_MIGRATION_LOCK_KEY = 0x4741485F4D494752  # "GAH_MIGR" as a signed-safe int8.
_LEGACY_V1_TABLES = frozenset(
    {
        "gah_run_heads",
        "gah_evidence_events",
        "gah_effect_executions",
        "gah_grant_consumptions",
    }
)


class MigrationError(RuntimeError):
    """Raised when schema installation cannot be proved safe."""


@dataclass(frozen=True, slots=True)
class Migration:
    """One immutable packaged migration."""

    version: int
    name: str
    checksum: str
    sql: str


class _Connection(Protocol):
    def __enter__(self) -> _Connection: ...

    def __exit__(self, *values: object) -> None: ...

    def cursor(self) -> Any: ...


def discover_migrations() -> tuple[Migration, ...]:
    """Load the complete, contiguous packaged migration sequence."""

    root = files("governed_agent_harness.persistence.migrations")
    discovered: list[Migration] = []
    malformed: list[str] = []
    for resource in root.iterdir():
        if not resource.name.endswith(".sql"):
            continue
        match = _MIGRATION_NAME.fullmatch(resource.name)
        if match is None:
            malformed.append(resource.name)
            continue
        payload = resource.read_bytes()
        discovered.append(
            Migration(
                version=int(match.group("version")),
                name=resource.name,
                checksum=f"sha256:{hashlib.sha256(payload).hexdigest()}",
                sql=payload.decode("utf-8"),
            )
        )
    if malformed:
        raise MigrationError(
            "packaged SQL migrations have invalid immutable names: " + ", ".join(sorted(malformed))
        )
    discovered.sort(key=lambda migration: migration.version)
    versions = [migration.version for migration in discovered]
    expected = list(range(1, len(discovered) + 1))
    if not discovered or versions != expected:
        raise MigrationError(
            f"packaged migration versions must be contiguous from 0001; found {versions}"
        )
    return tuple(discovered)


def apply_migrations(*, admin_connect: Callable[[], _Connection]) -> tuple[Migration, ...]:
    """Verify and apply packaged migrations in one locked database transaction.

    Connections in autocommit mode are rejected because a failed multi-statement
    migration must never leave a partially installed schema.
    """

    migrations = discover_migrations()
    with admin_connect() as connection:
        if getattr(connection, "autocommit", False):
            raise MigrationError("migration connection must not use autocommit")
        with connection.cursor() as cursor:
            cursor.execute("SELECT current_schema()")
            schema_row = cursor.fetchone()
            schema = schema_row[0] if schema_row else None
            if schema != "public":
                raise MigrationError(
                    "governed-agent-harness migrations require current_schema() = public"
                )
            cursor.execute("SELECT pg_advisory_xact_lock(%s)", (_MIGRATION_LOCK_KEY,))

            registry_exists = _relation_kind(cursor, schema, "gah_schema_migrations")
            if registry_exists is None:
                applied = _bootstrap(cursor, schema, migrations)
            else:
                if registry_exists != "r":
                    raise MigrationError("migration registry exists but is not an ordinary table")
                _verify_registry_shape(cursor, schema)
                applied = _read_applied(cursor, schema)
                existing_relations = _gah_relations(cursor, schema) - {"gah_schema_migrations"}
                if not applied and existing_relations:
                    raise MigrationError(
                        "unsafe bootstrap state: an empty registry accompanies existing GAH tables"
                    )

            _verify_applied(applied, migrations)
            applied_versions = {version for version, _checksum in applied}
            for migration in migrations:
                if migration.version in applied_versions:
                    continue
                _set_local_search_path(cursor, schema)
                cursor.execute(migration.sql)
                _insert_applied(cursor, schema, migration)
                applied_versions.add(migration.version)
    return migrations


def _bootstrap(
    cursor: Any, schema: str, migrations: tuple[Migration, ...]
) -> list[tuple[int, str]]:
    relations = _gah_relations(cursor, schema)
    if not relations:
        _create_registry(cursor, schema)
        return []
    if relations != _LEGACY_V1_TABLES:
        raise MigrationError(
            "unsafe bootstrap state: expected an empty schema or the exact Phase 4 table set"
        )
    if migrations[0].version != 1 or not _matches_legacy_v1(cursor, schema, migrations[0]):
        raise MigrationError(
            "unsafe bootstrap state: existing Phase 4 tables do not exactly match migration 0001"
        )
    _create_registry(cursor, schema)
    _insert_applied(cursor, schema, migrations[0])
    return [(migrations[0].version, migrations[0].checksum)]


def _verify_applied(applied: list[tuple[int, str]], migrations: tuple[Migration, ...]) -> None:
    known = {migration.version: migration for migration in migrations}
    versions = [version for version, _checksum in applied]
    if versions != list(range(1, len(versions) + 1)):
        raise MigrationError(f"applied migration history is non-contiguous: {versions}")
    for version, checksum in applied:
        migration = known.get(version)
        if migration is None:
            raise MigrationError(f"database contains unknown migration version {version:04d}")
        if checksum != migration.checksum:
            raise MigrationError(f"migration checksum drift detected for version {version:04d}")


def _create_registry(cursor: Any, schema: str) -> None:
    from psycopg import sql

    registry = sql.Identifier(schema, "gah_schema_migrations")
    cursor.execute(
        sql.SQL(
            "CREATE TABLE {} ("
            "version integer PRIMARY KEY, "
            "checksum text NOT NULL CHECK (checksum ~ '^sha256:[0-9a-f]{{64}}$'), "
            "applied_at timestamptz NOT NULL DEFAULT clock_timestamp()"
            ")"
        ).format(registry)
    )
    cursor.execute(sql.SQL("REVOKE ALL ON {} FROM PUBLIC").format(registry))


def _verify_registry_shape(cursor: Any, schema: str) -> None:
    cursor.execute(
        """
        SELECT a.attname, pg_catalog.format_type(a.atttypid, a.atttypmod),
               a.attnotnull, coalesce(pg_get_expr(d.adbin, d.adrelid), '')
          FROM pg_catalog.pg_attribute AS a
          JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
          LEFT JOIN pg_catalog.pg_attrdef AS d
            ON d.adrelid = a.attrelid AND d.adnum = a.attnum
         WHERE n.nspname = %s AND c.relname = 'gah_schema_migrations'
           AND a.attnum > 0 AND NOT a.attisdropped
         ORDER BY a.attnum
        """,
        (schema,),
    )
    columns = cursor.fetchall()
    if columns != [
        ("version", "integer", True, ""),
        ("checksum", "text", True, ""),
        ("applied_at", "timestamp with time zone", True, "clock_timestamp()"),
    ]:
        raise MigrationError("migration registry has an incompatible column layout")
    cursor.execute(
        """
        SELECT c.contype, array_agg(a.attname ORDER BY u.ordinality)
          FROM pg_catalog.pg_constraint AS c
          JOIN pg_catalog.pg_class AS t ON t.oid = c.conrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
          LEFT JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS u(attnum, ordinality)
            ON true
          LEFT JOIN pg_catalog.pg_attribute AS a
            ON a.attrelid = t.oid AND a.attnum = u.attnum
         WHERE n.nspname = %s AND t.relname = 'gah_schema_migrations'
         GROUP BY c.oid, c.contype
         ORDER BY c.contype
        """,
        (schema,),
    )
    constraints = cursor.fetchall()
    if constraints != [("c", ["checksum"]), ("p", ["version"])]:
        raise MigrationError("migration registry has incompatible constraints")
    cursor.execute(
        """
        SELECT c.relrowsecurity, c.relforcerowsecurity, c.relhasrules,
               EXISTS (
                   SELECT 1 FROM pg_catalog.pg_trigger AS g
                    WHERE g.tgrelid = c.oid AND NOT g.tgisinternal
               ),
               has_table_privilege(
                   'public', c.oid,
                   'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'
               ),
               pg_get_userbyid(c.relowner)
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relname = 'gah_schema_migrations'
        """,
        (schema,),
    )
    security = cursor.fetchone()
    if security is None or security[:5] != (False, False, False, False, False):
        raise MigrationError("migration registry has unsafe security properties")
    if security[5] not in {"gah_schema_owner", _current_user(cursor)}:
        raise MigrationError("migration registry has an unexpected owner")


def _read_applied(cursor: Any, schema: str) -> list[tuple[int, str]]:
    from psycopg import sql

    cursor.execute(
        sql.SQL("SELECT version, checksum FROM {} ORDER BY version").format(
            sql.Identifier(schema, "gah_schema_migrations")
        )
    )
    return [(row[0], row[1]) for row in cursor.fetchall()]


def _insert_applied(cursor: Any, schema: str, migration: Migration) -> None:
    from psycopg import sql

    cursor.execute(
        sql.SQL("INSERT INTO {} (version, checksum) VALUES (%s, %s)").format(
            sql.Identifier(schema, "gah_schema_migrations")
        ),
        (migration.version, migration.checksum),
    )


def _relation_kind(cursor: Any, schema: str, name: str) -> str | None:
    cursor.execute(
        """
        SELECT c.relkind
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relname = %s
        """,
        (schema, name),
    )
    row = cursor.fetchone()
    return row[0] if row else None


def _gah_relations(cursor: Any, schema: str) -> frozenset[str]:
    cursor.execute(
        """
        SELECT c.relname
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relname LIKE 'gah!_%%' ESCAPE '!'
           AND c.relkind IN ('r', 'p', 'v', 'm', 'f')
        """,
        (schema,),
    )
    return frozenset(row[0] for row in cursor.fetchall())


def _matches_legacy_v1(cursor: Any, schema: str, migration: Migration) -> bool:
    """Compare legacy tables to a transaction-local schema built from migration 0001."""

    from psycopg import sql

    probe = "gah_migration_integrity_probe"
    if _schema_exists(cursor, probe):
        raise MigrationError("migration integrity probe schema already exists")
    cursor.execute(sql.SQL("CREATE SCHEMA {}").format(sql.Identifier(probe)))
    try:
        _set_local_search_path(cursor, probe)
        cursor.execute(migration.sql)
        expected = _schema_fingerprint(cursor, probe, _LEGACY_V1_TABLES)
        actual = _schema_fingerprint(cursor, schema, _LEGACY_V1_TABLES)
        return actual == expected
    finally:
        cursor.execute(sql.SQL("DROP SCHEMA {} CASCADE").format(sql.Identifier(probe)))
        _set_local_search_path(cursor, schema)


def _schema_fingerprint(
    cursor: Any, schema: str, table_names: Iterable[str]
) -> tuple[tuple[Any, ...], ...]:
    names = sorted(table_names)
    cursor.execute(
        """
        SELECT 'table', c.relname, c.relrowsecurity::text, c.relforcerowsecurity::text,
               coalesce(c.relacl::text, ''), pg_get_userbyid(c.relowner), '', ''
          FROM pg_catalog.pg_class AS c
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relname = ANY(%s) AND c.relkind = 'r'
        UNION ALL
        SELECT 'column', c.relname, a.attname,
               pg_catalog.format_type(a.atttypid, a.atttypmod),
               a.attnotnull::text, coalesce(pg_get_expr(d.adbin, d.adrelid), ''), '', ''
          FROM pg_catalog.pg_attribute AS a
          JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
          LEFT JOIN pg_catalog.pg_attrdef AS d
            ON d.adrelid = a.attrelid AND d.adnum = a.attnum
         WHERE n.nspname = %s AND c.relname = ANY(%s)
           AND a.attnum > 0 AND NOT a.attisdropped
        UNION ALL
        SELECT 'constraint', t.relname, c.contype::text,
               replace(replace(pg_get_constraintdef(c.oid, true),
                       quote_ident(%s) || '.', ''), quote_ident(%s) || '.', ''), '', '', '', ''
          FROM pg_catalog.pg_constraint AS c
          JOIN pg_catalog.pg_class AS t ON t.oid = c.conrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
         WHERE n.nspname = %s AND t.relname = ANY(%s)
        UNION ALL
        SELECT 'index', t.relname, i.relname,
               replace(replace(pg_get_indexdef(i.oid),
                       quote_ident(%s) || '.', ''), quote_ident(%s) || '.', ''), '', '', '', ''
          FROM pg_catalog.pg_index AS x
          JOIN pg_catalog.pg_class AS i ON i.oid = x.indexrelid
          JOIN pg_catalog.pg_class AS t ON t.oid = x.indrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
         WHERE n.nspname = %s AND t.relname = ANY(%s)
        UNION ALL
        SELECT 'trigger', t.relname, g.tgname,
               replace(replace(pg_get_triggerdef(g.oid, true),
                       quote_ident(%s) || '.', ''), quote_ident(%s) || '.', ''), '', '', '', ''
          FROM pg_catalog.pg_trigger AS g
          JOIN pg_catalog.pg_class AS t ON t.oid = g.tgrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = t.relnamespace
         WHERE n.nspname = %s AND t.relname = ANY(%s) AND NOT g.tgisinternal
        UNION ALL
        SELECT 'policy', c.relname, p.polname, p.polpermissive::text,
               p.polroles::text, p.polcmd::text,
               coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
               coalesce(pg_get_expr(p.polwithcheck, p.polrelid), '')
          FROM pg_catalog.pg_policy AS p
          JOIN pg_catalog.pg_class AS c ON c.oid = p.polrelid
          JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
         WHERE n.nspname = %s AND c.relname = ANY(%s)
         ORDER BY 1, 2, 3, 4, 5, 6, 7, 8
        """,
        (
            schema,
            names,
            schema,
            names,
            schema,
            schema,
            schema,
            names,
            schema,
            schema,
            schema,
            names,
            schema,
            schema,
            schema,
            names,
            schema,
            names,
        ),
    )
    return tuple(tuple(value for value in row) for row in cursor.fetchall())


def _schema_exists(cursor: Any, schema: str) -> bool:
    cursor.execute("SELECT 1 FROM pg_catalog.pg_namespace WHERE nspname = %s", (schema,))
    return cursor.fetchone() is not None


def _current_user(cursor: Any) -> str:
    cursor.execute("SELECT current_user")
    row = cursor.fetchone()
    if row is None or not isinstance(row[0], str):
        raise MigrationError("database current user is unavailable")
    return row[0]


def _set_local_search_path(cursor: Any, schema: str) -> None:
    from psycopg import sql

    cursor.execute(sql.SQL("SET LOCAL search_path = {}, pg_catalog").format(sql.Identifier(schema)))
