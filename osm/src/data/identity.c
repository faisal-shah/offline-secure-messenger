#include "identity.h"
#include "../app.h"
#include "../hal/hal_storage_util.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define IDENTITY_FILE "data_identity.json"

/* Simple JSON key extractor (reuse pattern from contacts/messages) */
static bool extract_json_string(const char *json, const char *key,
                                char *out, size_t out_len)
{
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "\"%s\"", key);
    const char *p = strstr(json, pattern);
    if (!p) return false;
    p += strlen(pattern);
    while (*p && *p != '"') p++;
    if (*p != '"') return false;
    p++;
    size_t i = 0;
    while (*p && *p != '"' && i < out_len - 1) {
        out[i++] = *p++;
    }
    out[i] = '\0';
    return i > 0;
}

bool identity_load(crypto_identity_t *id)
{
    memset(id, 0, sizeof(*id));
    id->valid = false;

    size_t n = 0;
    char *buf = hal_storage_read_file(IDENTITY_FILE, &n);
    if (!buf) return false;

    char pubkey_b64[CRYPTO_PUBKEY_B64_SIZE];
    char privkey_b64[CRYPTO_PUBKEY_B64_SIZE]; /* same size for 32 bytes */

    if (!extract_json_string(buf, "pubkey", pubkey_b64, sizeof(pubkey_b64)) ||
        !extract_json_string(buf, "privkey", privkey_b64, sizeof(privkey_b64))) {
        free(buf);
        memset(pubkey_b64, 0, sizeof(pubkey_b64));
        memset(privkey_b64, 0, sizeof(privkey_b64));
        return false;
    }

    free(buf);

    size_t pub_len = 0, priv_len = 0;
    bool ok = true;
    if (!crypto_b64_decode(pubkey_b64, id->pubkey, CRYPTO_PUBKEY_BYTES, &pub_len) ||
        pub_len != CRYPTO_PUBKEY_BYTES) {
        ok = false;
    }
    if (ok && (!crypto_b64_decode(privkey_b64, id->privkey, CRYPTO_PRIVKEY_BYTES, &priv_len) ||
        priv_len != CRYPTO_PRIVKEY_BYTES)) {
        ok = false;
    }

    /* Zero b64 buffers that held key material */
    memset(pubkey_b64, 0, sizeof(pubkey_b64));
    memset(privkey_b64, 0, sizeof(privkey_b64));

    if (!ok) return false;
    id->valid = true;
    return true;
}

void identity_save(const crypto_identity_t *id)
{
    char pubkey_b64[CRYPTO_PUBKEY_B64_SIZE];
    char privkey_b64[CRYPTO_PUBKEY_B64_SIZE];
    crypto_pubkey_to_b64(id->pubkey, pubkey_b64, sizeof(pubkey_b64));
    crypto_b64_encode(id->privkey, CRYPTO_PRIVKEY_BYTES,
                      privkey_b64, sizeof(privkey_b64));

    char buf[256];
    int len = snprintf(buf, sizeof(buf),
            "{\n  \"pubkey\": \"%s\",\n  \"privkey\": \"%s\"\n}\n",
            pubkey_b64, privkey_b64);
    if (!hal_storage_write_file(IDENTITY_FILE, buf, (size_t)len))
        g_app.storage_error = true;

    /* Zero b64 buffers that held key material */
    memset(pubkey_b64, 0, sizeof(pubkey_b64));
    memset(privkey_b64, 0, sizeof(privkey_b64));
}
