/* hal_log_posix.c — POSIX logging via stderr */
#include "hal/hal_log.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

void hal_log(const char *context, const char *msg)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[16];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    fprintf(stderr, "[%s] %s: %.60s%s\n",
            ts, context, msg, strlen(msg) > 60 ? "..." : "");
}
