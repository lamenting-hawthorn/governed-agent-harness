# Canonical v1 wire contracts

This directory is the wire authority for the 27 version `1.0` contract records
listed in `catalog.json`. Every record uses snake_case property names, a fixed
`schema_version` of `1.0`, and a fixed lowercase snake_case `record_type`.
Schemas use JSON Schema Draft 2020-12 and fail closed on undeclared properties.

Contract IDs are lowercase UUIDv7 values. Timestamps are RFC 3339 UTC values
with exactly three fractional-second digits. Digests are lowercase SHA-256
values prefixed by `sha256:` and are computed over RFC 8785 canonical bytes.
Digest equality, proof verification, chronology, tenant agreement across nested
objects, and idempotency conflict detection are cross-record validator duties.

Security-sensitive numeric fields are JSON Schema integers bounded to the safe
interoperable integer range. A strict decoder must reject floating-point number
tokens, duplicate object keys, non-finite values, and repaired or invalid
Unicode before schema validation because those lexical conditions are not
visible to a validator after ordinary JSON parsing. Decimal domain values must
use an explicitly declared string representation rather than a JSON number.

`extensions` permits at most 16 reverse-domain namespaced keys. Its key and
value bounds provide a schema-enforceable size approximation alongside the
8 KiB RFC 8785 canonical-byte cap. The exact byte cap is a validator duty.
Extension data is non-authoritative unless a versioned policy explicitly names
a key as mandatory.

Authorization constraints use closed records with namespaced constraint IDs,
versions, parameter digests, and bounded parameters. Validators must reject an
unregistered or unsupported constraint ID or version; unknown constraints never
degrade into an ignored field.

Protected payload references are tenant-bound and require an allowlisted URI,
digest, byte size, media type, encryption key identifier, and retention time.
URI authorization, key ownership, payload retrieval, digest verification, and
retention enforcement occur at the protected-payload boundary.

Evidence contracts describe append-only, tamper-evident records. They do not
promise tamper-proof storage. Effect contracts model indeterminate outcomes and
make no delivery-count guarantee. Learning artifacts remain inert until a
runtime-authority activation receipt verifies successfully. Legacy `applied`
state is not a v1 lifecycle value; migration maps it to `legacy_exported`.

Receipt proof objects contain exactly `issuer`, `key_id`, `algorithm`,
`proof_domain`, `object_digest`, `nonce`, and `detached_proof`. Receipt schemas
fix the proof domain. Trust-root allowlisting, algorithm policy, key rotation or
revocation, bounded clock skew, canonical-object reconstruction, replay checks,
and detached-proof verification are validator responsibilities.

For signed records, the top-level object digest is the RFC 8785 digest of the
defined unsigned body. `proof.object_digest` must equal that digest, and the
detached proof is verified in the declared proof domain. This equality and the
field-exclusion rules used to construct the unsigned body are validator duties.
