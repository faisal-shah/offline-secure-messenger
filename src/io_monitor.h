#ifndef IO_MONITOR_H
#define IO_MONITOR_H

#include "lvgl.h"

#define IO_MON_HOR_RES 500
#define IO_MON_VER_RES 400

/* Create I/O monitor UI on the given display */
void io_monitor_create(lv_display_t *disp);

/* Refresh simulation controls (call after data changes) */
void io_monitor_refresh(void);

/* Append an entry to the output log */
void io_monitor_log(const char *context, const char *data);

#endif
