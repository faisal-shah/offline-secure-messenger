#ifndef HAL_STORAGE_H
#define HAL_STORAGE_H

#include "lfs.h"
#include <stdbool.h>

/* Initialize the storage subsystem (mount or format+mount).
 * data_dir: directory for the backing file (desktop) or ignored (MCU).
 * Returns true on success. */
bool hal_storage_init(const char *data_dir);

/* Unmount and clean up. */
void hal_storage_deinit(void);

/* Get the mounted LittleFS handle for direct lfs_file_* calls. */
lfs_t *hal_storage_get(void);

#endif /* HAL_STORAGE_H */
