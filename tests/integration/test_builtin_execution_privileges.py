"""Role, ACL, RLS, and search-path proof for Phase 5.1 execution admission."""

from __future__ import annotations

import copy
import json

import pytest


RUNTIME_FUNCTIONS = (
    "gah_builtin_execution_evidence_head(jsonb,text)",
    "gah_lookup_builtin_execution(jsonb,jsonb)",
    "gah_begin_builtin_execution(jsonb,jsonb,jsonb,double precision)",
    "gah_complete_builtin_execution(jsonb,jsonb,jsonb,jsonb)",
    "gah_recover_builtin_execution(jsonb,jsonb,jsonb,jsonb)",
)
AUTHORITY_FUNCTIONS = (
    "gah_lookup_builtin_execution_authorization(jsonb,jsonb)",
    "gah_issue_builtin_execution_authorization(jsonb,jsonb,jsonb,jsonb,jsonb)",
    "gah_rebuild_builtin_execution(jsonb,jsonb)",
)
WRITER_FUNCTIONS = (
    "gah_authorize_builtin_execution(jsonb,jsonb)",
    "gah_commit_evidence(jsonb,jsonb)",
)


def test_execution_acl_is_narrow_and_security_definer_search_path_is_fixed(
    postgres_connections,
):
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        for function in (*RUNTIME_FUNCTIONS, *AUTHORITY_FUNCTIONS, *WRITER_FUNCTIONS):
            cursor.execute(
                "SELECT has_function_privilege('public', %s, 'EXECUTE')",
                (function,),
            )
            assert cursor.fetchone()[0] is False
            cursor.execute(
                "SELECT prosecdef, proconfig FROM pg_proc WHERE oid=%s::regprocedure",
                (function,),
            )
            security_definer, settings = cursor.fetchone()
            assert security_definer is True
            assert settings == ["search_path=pg_catalog, public"]
        for function in RUNTIME_FUNCTIONS:
            cursor.execute(
                "SELECT has_function_privilege('gah_runtime', %s, 'EXECUTE')",
                (function,),
            )
            assert cursor.fetchone()[0] is True
        for function in AUTHORITY_FUNCTIONS:
            cursor.execute(
                "SELECT has_function_privilege('gah_runtime', %s, 'EXECUTE')",
                (function,),
            )
            assert cursor.fetchone()[0] is False
            cursor.execute(
                "SELECT has_function_privilege('gah_execution_admission_authority', %s, 'EXECUTE')",
                (function,),
            )
            assert cursor.fetchone()[0] is True
        for function in WRITER_FUNCTIONS:
            cursor.execute(
                "SELECT has_function_privilege('gah_authority_writer', %s, 'EXECUTE')",
                (function,),
            )
            assert cursor.fetchone()[0] is True
            cursor.execute(
                "SELECT has_function_privilege('gah_execution_admission_authority', %s, 'EXECUTE')",
                (function,),
            )
            assert cursor.fetchone()[0] is False
        cursor.execute(
            "SELECT has_table_privilege('gah_runtime', "
            "'gah_builtin_execution_state', 'SELECT,INSERT,UPDATE,DELETE')"
        )
        assert cursor.fetchone()[0] is False
        cursor.execute(
            "SELECT has_table_privilege('gah_runtime', "
            "'gah_execution_proof_keys', 'SELECT,INSERT,UPDATE,DELETE')"
        )
        assert cursor.fetchone()[0] is False
        cursor.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid='gah_builtin_execution_state'::regclass"
        )
        assert cursor.fetchone() == (True, True)
        cursor.execute(
            "SELECT relrowsecurity, relforcerowsecurity FROM pg_class "
            "WHERE oid='gah_execution_proof_keys'::regclass"
        )
        assert cursor.fetchone() == (True, True)
        cursor.execute(
            "SELECT has_schema_privilege('gah_runtime', 'gah_crypto', 'USAGE'), "
            "has_function_privilege('gah_runtime', "
            "'gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)', 'EXECUTE')"
        )
        assert cursor.fetchone() == (False, False)
        cursor.execute(
            "SELECT extension.extversion, namespace.nspname, language.lanname, "
            "procedure.probin, procedure.prosrc, procedure.proisstrict, "
            "procedure.provolatile, procedure.proparallel, "
            "pg_get_userbyid(extension.extowner), pg_get_userbyid(procedure.proowner), "
            "EXISTS (SELECT 1 FROM pg_depend AS dependency "
            "WHERE dependency.classid='pg_proc'::regclass "
            "AND dependency.objid=procedure.oid "
            "AND dependency.refclassid='pg_extension'::regclass "
            "AND dependency.refobjid=extension.oid AND dependency.deptype='e') "
            "FROM pg_extension AS extension "
            "JOIN pg_namespace AS namespace ON namespace.oid=extension.extnamespace "
            "JOIN pg_proc AS procedure ON procedure.oid=to_regprocedure("
            "'gah_crypto.ed25519_verify_detached(bytea,bytea,bytea)') "
            "JOIN pg_language AS language ON language.oid=procedure.prolang "
            "WHERE extension.extname='gah_ed25519'"
        )
        native_identity = cursor.fetchone()
        cursor.execute("SELECT current_user")
        installing_admin = cursor.fetchone()
    assert installing_admin is not None
    assert native_identity == (
        "1.0",
        "gah_crypto",
        "c",
        "$libdir/gah_ed25519",
        "gah_ed25519_verify_detached",
        True,
        "i",
        "s",
        installing_admin[0],
        "gah_schema_owner",
        True,
    )
    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT rolcanlogin, rolsuper, rolcreatedb, rolcreaterole, rolinherit, "
            "rolreplication, rolbypassrls FROM pg_roles "
            "WHERE rolname='gah_execution_admission_authority'"
        )
        assert cursor.fetchone() == (False, False, False, False, False, False, False)


def test_runtime_and_authority_credentials_cannot_cross_entrypoints(postgres_connections):
    with postgres_connections["app"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute("SELECT * FROM gah_builtin_execution_state")
        connection.rollback()
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                "SELECT gah_issue_builtin_execution_authorization"
                "('{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'{}'::jsonb,'{}'::jsonb)"
            )
    with postgres_connections["writer"]() as connection, connection.cursor() as cursor:
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                "SELECT gah_begin_builtin_execution('{}'::jsonb,'{}'::jsonb,'{}'::jsonb,1)"
            )
        connection.rollback()
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute("SELECT gah_rebuild_builtin_execution('{}'::jsonb,'{}'::jsonb)")
    with (
        postgres_connections["execution_authority"]() as connection,
        connection.cursor() as cursor,
    ):
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute("SELECT gah_authorize_builtin_execution('{}'::jsonb,'{}'::jsonb)")
        connection.rollback()
        with pytest.raises(Exception, match="permission denied"):
            cursor.execute(
                "SELECT gah_begin_builtin_execution('{}'::jsonb,'{}'::jsonb,'{}'::jsonb,1)"
            )


@pytest.mark.parametrize(
    ("container", "field"),
    (
        ("actor", "tenant_id"),
        ("actor", "actor_id"),
        ("actor", "session_id"),
        ("binding", "purpose"),
        ("binding", "operation_id"),
        ("binding", "operation_digest"),
        ("binding", "command_digest"),
        ("binding", "grant_digest"),
        ("binding", "request_id"),
        ("binding", "request_digest"),
    ),
)
def test_writer_lock_commitment_binds_every_authority_field(
    postgres_connections,
    container,
    field,
):
    actor = {
        "tenant_id": "018f0000-0000-7000-8000-000000000001",
        "actor_id": "018f0000-0000-7000-8000-000000000002",
        "session_id": "018f0000-0000-7000-8000-000000000003",
    }
    binding = {
        "purpose": "issue",
        "operation_id": "phase5-lock-binding",
        "operation_digest": "sha256:" + "1" * 64,
        "command_digest": "sha256:" + "2" * 64,
        "grant_digest": "sha256:" + "3" * 64,
        "request_id": "018f0000-0000-7000-8000-000000000004",
        "request_digest": "sha256:" + "4" * 64,
    }
    changed_actor = copy.deepcopy(actor)
    changed_binding = copy.deepcopy(binding)
    target = changed_actor if container == "actor" else changed_binding
    target[field] = f"{target[field]}.changed"

    with postgres_connections["admin"]() as connection, connection.cursor() as cursor:
        cursor.execute(
            "SELECT * FROM gah_builtin_execution_writer_lock_keys(%s::jsonb,%s::jsonb)",
            (json.dumps(actor), json.dumps(binding)),
        )
        original = cursor.fetchone()
        cursor.execute(
            "SELECT * FROM gah_builtin_execution_writer_lock_keys(%s::jsonb,%s::jsonb)",
            (
                json.dumps(changed_actor),
                json.dumps(changed_binding),
            ),
        )
        changed = cursor.fetchone()

    assert changed != original
