/* hal_rng_posix.c — POSIX random number generation via /dev/urandom */
#include "hal/hal_rng.h"
#include <stdio.h>

void hal_random_bytes(void *buf, size_t len)
{
    FILE *f = fopen("/dev/urandom", "r");
    if (f) {
        fread(buf, 1, len, f);
        fclose(f);
    }
}
