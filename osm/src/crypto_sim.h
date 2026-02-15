#ifndef CRYPTO_SIM_H
#define CRYPTO_SIM_H

#include <stdint.h>
#include <stddef.h>

/* Fake DH key generation — returns hex-looking string */
void crypto_sim_generate_dh_pubkey(char *out, size_t out_len);

/* Fake encrypt: base64-ish encoding with contact ID prefix */
void crypto_sim_encrypt(const char *plaintext, uint32_t contact_id,
                        char *ciphertext, size_t ct_len);

/* Fake decrypt: reverse of encrypt */
void crypto_sim_decrypt(const char *ciphertext, char *plaintext, size_t pt_len,
                        uint32_t *contact_id_out);

#endif
