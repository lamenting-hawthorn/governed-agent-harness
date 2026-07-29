CREATE FUNCTION ed25519_verify_detached(signature bytea, message bytea, public_key bytea)
RETURNS boolean
AS 'MODULE_PATHNAME', 'gah_ed25519_verify_detached'
LANGUAGE C
STRICT
IMMUTABLE
PARALLEL SAFE;

REVOKE ALL ON FUNCTION gah_crypto.ed25519_verify_detached(bytea, bytea, bytea) FROM PUBLIC;
