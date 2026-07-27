"""Database-role and migration proof for the Phase 4.4 inert skill boundary."""

from __future__ import annotations


def test_skill_registry_is_migrated_and_runtime_has_only_resolve_access(postgres_connections):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT to_regclass('gah_skill_artifact_revisions'), "
            "to_regclass('gah_skill_lifecycle_transitions'), "
            "to_regclass('gah_active_skill_projection'), "
            "has_function_privilege('gah_app', 'gah_resolve_active_skill(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_app', 'gah_install_skill(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_writer', 'gah_install_skill(jsonb,jsonb)', 'EXECUTE'), "
            "has_function_privilege('gah_skill_authority', 'gah_install_skill(jsonb,jsonb)', 'EXECUTE'), "
            "has_table_privilege('gah_app', 'gah_skill_artifact_revisions', 'SELECT')"
        )
        assert cursor.fetchone() == (
            "gah_skill_artifact_revisions",
            "gah_skill_lifecycle_transitions",
            "gah_active_skill_projection",
            True,
            False,
            False,
            True,
            False,
        )
