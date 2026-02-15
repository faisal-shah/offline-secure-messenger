#ifndef HAL_RNG_H
#define HAL_RNG_H

#include <stddef.h>

/* Fill buf with len cryptographically secure random bytes. */
void hal_random_bytes(void *buf, size_t len);

#endif /* HAL_RNG_H */
