#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define CRYPTO_PUBKEY_BYTES   32
#define CRYPTO_PRIVKEY_BYTES  32
#define CRYPTO_NONCE_BYTES    24
#define CRYPTO_MAC_BYTES      16
#define CRYPTO_PUBKEY_B64_SIZE 45  /* ceil(32/3)*4 + NUL */

typedef struct {
    uint8_t pubkey[CRYPTO_PUBKEY_BYTES];
    uint8_t privkey[CRYPTO_PRIVKEY_BYTES];
    bool    valid;
} crypto_identity_t;

/* Generate X25519 keypair */
void crypto_generate_keypair(crypto_identity_t *id);

/**
 * Encrypt plaintext for a peer.
 * Output is base64([24-byte nonce][ciphertext+MAC]).
 * Returns true on success.
 */
bool crypto_encrypt(const char *plaintext,
                    const uint8_t peer_pubkey[CRYPTO_PUBKEY_BYTES],
                    const uint8_t my_privkey[CRYPTO_PRIVKEY_BYTES],
                    char *out_b64, size_t out_b64_len);

/**
 * Decrypt base64-encoded ciphertext from a peer.
 * Returns true on success (authentication passed).
 */
bool crypto_decrypt(const char *cipher_b64,
                    const uint8_t peer_pubkey[CRYPTO_PUBKEY_BYTES],
                    const uint8_t my_privkey[CRYPTO_PRIVKEY_BYTES],
                    char *plaintext, size_t pt_len);

/* Base64 encode/decode */
size_t crypto_b64_encode(const uint8_t *src, size_t src_len,
                         char *dst, size_t dst_len);
bool   crypto_b64_decode(const char *src,
                         uint8_t *dst, size_t dst_len, size_t *out_len);

/* Pubkey ↔ base64 convenience */
void crypto_pubkey_to_b64(const uint8_t pubkey[CRYPTO_PUBKEY_BYTES],
                          char *out, size_t out_len);
bool crypto_b64_to_pubkey(const char *b64,
                          uint8_t pubkey[CRYPTO_PUBKEY_BYTES]);

#endif /* CRYPTO_H */
