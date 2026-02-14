#include "crypto_sim.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

static const char b64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void crypto_sim_generate_dh_pubkey(char *out, size_t out_len)
{
    /* Generate a fake hex public key */
    static int seeded = 0;
    if (!seeded) { srand(time(NULL)); seeded = 1; }

    const char hex[] = "0123456789abcdef";
    size_t len = (out_len - 1 < 64) ? out_len - 1 : 64;
    for (size_t i = 0; i < len; i++) {
        out[i] = hex[rand() % 16];
    }
    out[len] = '\0';
}

void crypto_sim_encrypt(const char *plaintext, uint32_t contact_id,
                        char *ciphertext, size_t ct_len)
{
    /* Format: "SC:<contact_id>:<base64(plaintext)>" */
    char prefix[32];
    snprintf(prefix, sizeof(prefix), "SC:%u:", contact_id);
    size_t plen = strlen(prefix);
    memcpy(ciphertext, prefix, plen);

    /* Simple base64 encode */
    size_t slen = strlen(plaintext);
    size_t j = plen;
    for (size_t i = 0; i < slen && j + 4 < ct_len; i += 3) {
        uint32_t n = (uint8_t)plaintext[i] << 16;
        if (i + 1 < slen) n |= (uint8_t)plaintext[i + 1] << 8;
        if (i + 2 < slen) n |= (uint8_t)plaintext[i + 2];

        ciphertext[j++] = b64[(n >> 18) & 0x3F];
        ciphertext[j++] = b64[(n >> 12) & 0x3F];
        ciphertext[j++] = (i + 1 < slen) ? b64[(n >> 6) & 0x3F] : '=';
        ciphertext[j++] = (i + 2 < slen) ? b64[n & 0x3F] : '=';
    }
    ciphertext[j] = '\0';
}

/* Simple base64 decode helper */
static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

void crypto_sim_decrypt(const char *ciphertext, char *plaintext, size_t pt_len,
                        uint32_t *contact_id_out)
{
    *contact_id_out = 0;
    plaintext[0] = '\0';

    /* Parse "SC:<id>:<base64>" */
    if (strncmp(ciphertext, "SC:", 3) != 0) return;

    const char *p = ciphertext + 3;
    *contact_id_out = (uint32_t)strtoul(p, NULL, 10);

    p = strchr(p, ':');
    if (!p) return;
    p++;

    /* Base64 decode */
    size_t j = 0;
    size_t slen = strlen(p);
    for (size_t i = 0; i < slen && j < pt_len - 1; i += 4) {
        int a = b64_val(p[i]);
        int b = (i + 1 < slen) ? b64_val(p[i + 1]) : 0;
        int c = (i + 2 < slen) ? b64_val(p[i + 2]) : 0;
        int d = (i + 3 < slen) ? b64_val(p[i + 3]) : 0;
        if (a < 0) a = 0;
        if (b < 0) b = 0;

        uint32_t n = (a << 18) | (b << 12) | (c << 6) | d;
        if (j < pt_len - 1) plaintext[j++] = (n >> 16) & 0xFF;
        if (i + 2 < slen && p[i + 2] != '=' && j < pt_len - 1)
            plaintext[j++] = (n >> 8) & 0xFF;
        if (i + 3 < slen && p[i + 3] != '=' && j < pt_len - 1)
            plaintext[j++] = n & 0xFF;
    }
    plaintext[j] = '\0';
}
