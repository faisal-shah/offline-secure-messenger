#include "crypto.h"
#include "tweetnacl.h"
#include "hal/hal_rng.h"
#include <string.h>
#include <stdio.h>

/* ---- randombytes (required by TweetNaCl) — delegates to HAL ---- */
void randombytes(unsigned char *buf, unsigned long long len)
{
    hal_random_bytes(buf, (size_t)len);
}

/* ---- Base64 ---- */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

size_t crypto_b64_encode(const uint8_t *src, size_t src_len,
                         char *dst, size_t dst_len)
{
    size_t out_len = ((src_len + 2) / 3) * 4;
    if (dst_len < out_len + 1) return 0;

    size_t j = 0;
    for (size_t i = 0; i < src_len; i += 3) {
        uint32_t n = (uint32_t)src[i] << 16;
        if (i + 1 < src_len) n |= (uint32_t)src[i + 1] << 8;
        if (i + 2 < src_len) n |= (uint32_t)src[i + 2];

        dst[j++] = b64_table[(n >> 18) & 0x3F];
        dst[j++] = b64_table[(n >> 12) & 0x3F];
        dst[j++] = (i + 1 < src_len) ? b64_table[(n >> 6) & 0x3F] : '=';
        dst[j++] = (i + 2 < src_len) ? b64_table[n & 0x3F] : '=';
    }
    dst[j] = '\0';
    return j;
}

static int b64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

bool crypto_b64_decode(const char *src,
                       uint8_t *dst, size_t dst_len, size_t *out_len)
{
    size_t slen = strlen(src);
    while (slen > 0 && src[slen - 1] == '=') slen--;

    size_t max_out = (slen * 3) / 4;
    if (dst_len < max_out) return false;

    size_t j = 0;
    for (size_t i = 0; i < slen; i += 4) {
        int a = b64_val(src[i]);
        int b = (i + 1 < slen) ? b64_val(src[i + 1]) : 0;
        int c = (i + 2 < slen) ? b64_val(src[i + 2]) : 0;
        int d = (i + 3 < slen) ? b64_val(src[i + 3]) : 0;
        if (a < 0 || b < 0) return false;

        uint32_t n = ((uint32_t)a << 18) | ((uint32_t)b << 12) |
                     ((uint32_t)c << 6) | (uint32_t)d;
        dst[j++] = (uint8_t)(n >> 16);
        if (i + 2 < slen && c >= 0) dst[j++] = (uint8_t)(n >> 8);
        if (i + 3 < slen && d >= 0) dst[j++] = (uint8_t)n;
    }
    if (out_len) *out_len = j;
    return true;
}

void crypto_pubkey_to_b64(const uint8_t pubkey[CRYPTO_PUBKEY_BYTES],
                          char *out, size_t out_len)
{
    crypto_b64_encode(pubkey, CRYPTO_PUBKEY_BYTES, out, out_len);
}

bool crypto_b64_to_pubkey(const char *b64,
                          uint8_t pubkey[CRYPTO_PUBKEY_BYTES])
{
    size_t len = 0;
    if (!crypto_b64_decode(b64, pubkey, CRYPTO_PUBKEY_BYTES, &len))
        return false;
    return len == CRYPTO_PUBKEY_BYTES;
}

/* ---- Key generation ---- */
void crypto_generate_keypair(crypto_identity_t *id)
{
    crypto_box_keypair(id->pubkey, id->privkey);
    id->valid = true;
}

/* Max work buffer for encrypt/decrypt (1024 text + crypto_box overhead) */
#define CRYPTO_MAX_PADDED  (1024 + 64)  /* ~1088, covers ZEROBYTES padding */
#define CRYPTO_MAX_RAW     (CRYPTO_MAX_PADDED + CRYPTO_NONCE_BYTES)

/* ---- Encrypt ---- */
bool crypto_encrypt(const char *plaintext,
                    const uint8_t peer_pubkey[CRYPTO_PUBKEY_BYTES],
                    const uint8_t my_privkey[CRYPTO_PRIVKEY_BYTES],
                    char *out_b64, size_t out_b64_len)
{
    size_t pt_len = strlen(plaintext);
    size_t padded_len = pt_len + crypto_box_ZEROBYTES;

    if (padded_len > CRYPTO_MAX_PADDED) return false;

    /* Stack-allocated work buffers */
    uint8_t m[CRYPTO_MAX_PADDED];
    uint8_t c[CRYPTO_MAX_PADDED];
    memset(m, 0, padded_len);
    memset(c, 0, padded_len);

    memcpy(m + crypto_box_ZEROBYTES, plaintext, pt_len);

    /* Generate random nonce */
    uint8_t nonce[CRYPTO_NONCE_BYTES];
    randombytes(nonce, CRYPTO_NONCE_BYTES);

    /* Encrypt */
    if (crypto_box(c, m, padded_len, nonce, peer_pubkey, my_privkey) != 0) {
        memset(m, 0, padded_len);
        memset(c, 0, padded_len);
        return false;
    }

    /* Output: [nonce (24)][ciphertext without BOXZEROBYTES padding] */
    size_t ct_payload = padded_len - crypto_box_BOXZEROBYTES;
    size_t raw_len = CRYPTO_NONCE_BYTES + ct_payload;
    uint8_t raw[CRYPTO_MAX_RAW];

    memcpy(raw, nonce, CRYPTO_NONCE_BYTES);
    memcpy(raw + CRYPTO_NONCE_BYTES, c + crypto_box_BOXZEROBYTES, ct_payload);

    size_t encoded = crypto_b64_encode(raw, raw_len, out_b64, out_b64_len);

    /* Zero sensitive buffers */
    memset(m, 0, padded_len);
    memset(c, 0, padded_len);
    memset(raw, 0, raw_len);
    return encoded > 0;
}

/* ---- Decrypt ---- */
bool crypto_decrypt(const char *cipher_b64,
                    const uint8_t peer_pubkey[CRYPTO_PUBKEY_BYTES],
                    const uint8_t my_privkey[CRYPTO_PRIVKEY_BYTES],
                    char *plaintext, size_t pt_len)
{
    /* Decode base64 */
    size_t b64_len = strlen(cipher_b64);
    size_t max_raw = (b64_len * 3) / 4 + 4;
    if (max_raw > CRYPTO_MAX_RAW) return false;

    uint8_t raw[CRYPTO_MAX_RAW];
    size_t raw_len = 0;
    if (!crypto_b64_decode(cipher_b64, raw, max_raw, &raw_len) ||
        raw_len < CRYPTO_NONCE_BYTES + CRYPTO_MAC_BYTES + 1) {
        return false;
    }

    /* Extract nonce and ciphertext payload */
    uint8_t nonce[CRYPTO_NONCE_BYTES];
    memcpy(nonce, raw, CRYPTO_NONCE_BYTES);

    size_t ct_payload = raw_len - CRYPTO_NONCE_BYTES;
    size_t padded_len = ct_payload + crypto_box_BOXZEROBYTES;

    if (padded_len > CRYPTO_MAX_PADDED) return false;

    uint8_t c[CRYPTO_MAX_PADDED];
    uint8_t m[CRYPTO_MAX_PADDED];
    memset(c, 0, padded_len);
    memset(m, 0, padded_len);

    memcpy(c + crypto_box_BOXZEROBYTES, raw + CRYPTO_NONCE_BYTES, ct_payload);
    memset(raw, 0, raw_len);

    /* Decrypt and authenticate */
    if (crypto_box_open(m, c, padded_len, nonce, peer_pubkey, my_privkey) != 0) {
        memset(c, 0, padded_len);
        memset(m, 0, padded_len);
        return false;
    }

    /* Extract plaintext (after ZEROBYTES padding) */
    size_t actual_pt = padded_len - crypto_box_ZEROBYTES;
    if (actual_pt >= pt_len) actual_pt = pt_len - 1;
    memcpy(plaintext, m + crypto_box_ZEROBYTES, actual_pt);
    plaintext[actual_pt] = '\0';

    /* Zero sensitive buffers */
    memset(c, 0, padded_len);
    memset(m, 0, padded_len);
    return true;
}
