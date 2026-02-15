#ifndef HAL_STORAGE_UTIL_H
#define HAL_STORAGE_UTIL_H

#include "hal/hal_storage.h"
#include <stdlib.h>
#include <string.h>

/* Read entire file into a malloc'd buffer. Caller must free().
 * Returns NULL if file doesn't exist or is empty.
 * Sets *out_len to the number of bytes read (excluding NUL terminator). */
static inline char *hal_storage_read_file(const char *path, size_t *out_len)
{
    lfs_t *lfs = hal_storage_get();
    if (!lfs) return NULL;

    lfs_file_t f;
    if (lfs_file_open(lfs, &f, path, LFS_O_RDONLY) < 0) return NULL;

    lfs_soff_t size = lfs_file_size(lfs, &f);
    if (size <= 0) { lfs_file_close(lfs, &f); return NULL; }

    char *buf = malloc((size_t)size + 1);
    if (!buf) { lfs_file_close(lfs, &f); return NULL; }

    lfs_ssize_t n = lfs_file_read(lfs, &f, buf, (lfs_size_t)size);
    lfs_file_close(lfs, &f);

    if (n <= 0) { free(buf); return NULL; }
    buf[n] = '\0';
    if (out_len) *out_len = (size_t)n;
    return buf;
}

/* Write buffer to a file (create/truncate). Returns true on success. */
static inline bool hal_storage_write_file(const char *path,
                                          const void *data, size_t len)
{
    lfs_t *lfs = hal_storage_get();
    if (!lfs) return false;

    lfs_file_t f;
    int flags = LFS_O_WRONLY | LFS_O_CREAT | LFS_O_TRUNC;
    if (lfs_file_open(lfs, &f, path, flags) < 0) return false;

    lfs_ssize_t n = lfs_file_write(lfs, &f, data, (lfs_size_t)len);
    lfs_file_close(lfs, &f);
    return n == (lfs_ssize_t)len;
}

#endif /* HAL_STORAGE_UTIL_H */
