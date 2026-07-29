-- Phase 4.4 remediation: generic durable writers are not skill lifecycle
-- authorities.  Lifecycle admission stays behind the dedicated service login.
DO $roles$
DECLARE
    role_record record;
BEGIN
    SELECT * INTO role_record FROM pg_roles WHERE rolname = 'gah_skill_lifecycle_authority';
    IF NOT FOUND THEN
        CREATE ROLE gah_skill_lifecycle_authority NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
            NOINHERIT NOREPLICATION NOBYPASSRLS;
    ELSIF role_record.rolcanlogin OR role_record.rolsuper OR role_record.rolcreatedb
        OR role_record.rolcreaterole OR role_record.rolinherit OR role_record.rolreplication
        OR role_record.rolbypassrls THEN
        RAISE EXCEPTION 'existing gah_skill_lifecycle_authority role has unsafe attributes';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_auth_members
         WHERE member = (SELECT oid FROM pg_roles WHERE rolname = 'gah_skill_lifecycle_authority')
    ) THEN
        RAISE EXCEPTION 'existing gah_skill_lifecycle_authority role has unsafe memberships';
    END IF;
END
$roles$;

REVOKE EXECUTE ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb),
    gah_install_skill(jsonb,jsonb), gah_activate_skill(jsonb,jsonb),
    gah_rollback_skill(jsonb,jsonb), gah_deactivate_skill(jsonb,jsonb),
    gah_rebuild_skill_projection(jsonb,jsonb) FROM gah_authority_writer;
GRANT EXECUTE ON FUNCTION gah_lookup_skill_replay(jsonb,jsonb),
    gah_install_skill(jsonb,jsonb), gah_activate_skill(jsonb,jsonb),
    gah_rollback_skill(jsonb,jsonb), gah_deactivate_skill(jsonb,jsonb),
    gah_rebuild_skill_projection(jsonb,jsonb) TO gah_skill_lifecycle_authority;
GRANT USAGE ON SCHEMA public TO gah_skill_lifecycle_authority;
