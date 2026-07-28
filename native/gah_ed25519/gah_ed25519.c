#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"
#include "varatt.h"

#include <sodium.h>
#include <stdio.h>

PG_MODULE_MAGIC;

#define GAH_ED25519_MAX_MESSAGE_BYTES (1024 * 1024)

#if SODIUM_LIBRARY_VERSION_MAJOR < 10
#error "gah_ed25519 requires libsodium >= 1.0.20"
#endif

static void
gah_require_supported_libsodium(void)
{
    unsigned int major = 0;
    unsigned int minor = 0;
    unsigned int patch = 0;

    if (sodium_init() < 0)
        ereport(ERROR, (errcode(ERRCODE_EXTERNAL_ROUTINE_EXCEPTION),
                        errmsg("gah_ed25519 initialization failed")));
    if (sscanf(sodium_version_string(), "%u.%u.%u", &major, &minor, &patch) != 3 ||
        major != 1 || (minor == 0 && patch < 20))
        ereport(ERROR, (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                        errmsg("gah_ed25519 requires supported libsodium")));
}

PG_FUNCTION_INFO_V1(gah_ed25519_verify_detached);

Datum
gah_ed25519_verify_detached(PG_FUNCTION_ARGS)
{
    bytea *signature;
    bytea *message;
    bytea *public_key;
    int signature_length;
    int message_length;
    int public_key_length;

    gah_require_supported_libsodium();
    signature = PG_GETARG_BYTEA_PP(0);
    message = PG_GETARG_BYTEA_PP(1);
    public_key = PG_GETARG_BYTEA_PP(2);
    signature_length = VARSIZE_ANY_EXHDR(signature);
    message_length = VARSIZE_ANY_EXHDR(message);
    public_key_length = VARSIZE_ANY_EXHDR(public_key);
    if (signature_length != crypto_sign_BYTES ||
        public_key_length != crypto_sign_PUBLICKEYBYTES ||
        message_length > GAH_ED25519_MAX_MESSAGE_BYTES)
        ereport(ERROR, (errcode(ERRCODE_INVALID_PARAMETER_VALUE),
                        errmsg("gah_ed25519 input is invalid")));
    PG_RETURN_BOOL(
        crypto_sign_verify_detached((const unsigned char *) VARDATA_ANY(signature),
                                    (const unsigned char *) VARDATA_ANY(message),
                                    (unsigned long long) message_length,
                                    (const unsigned char *) VARDATA_ANY(public_key)) == 0);
}
