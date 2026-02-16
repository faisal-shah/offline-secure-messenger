/* hal_time_posix.c — POSIX time implementation */
#include "hal/hal_time.h"
#include <time.h>
#include <unistd.h>

uint32_t hal_get_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

void hal_delay_ms(uint32_t ms)
{
    usleep(ms * 1000);
}
