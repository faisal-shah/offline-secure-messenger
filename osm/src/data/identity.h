#ifndef IDENTITY_H
#define IDENTITY_H

#include "../crypto.h"

/* Load identity from data_identity.json. Returns true if valid keypair exists. */
bool identity_load(crypto_identity_t *id);

/* Save identity to data_identity.json. */
void identity_save(const crypto_identity_t *id);

#endif /* IDENTITY_H */
