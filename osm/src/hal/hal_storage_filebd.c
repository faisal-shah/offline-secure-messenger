/* hal_storage_filebd.c — Desktop LittleFS storage using file-backed block device */
#include "hal/hal_storage.h"
#include "bd/lfs_filebd.h"
#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE  4096
#define BLOCK_COUNT 256   /* 1 MB virtual flash */

static lfs_t lfs;
static lfs_filebd_t bd;
static struct lfs_config cfg;
static struct lfs_filebd_config bd_cfg;
static bool mounted;
static char backing_path[512];

bool hal_storage_init(const char *data_dir)
{
    if (mounted) return true;

    snprintf(backing_path, sizeof(backing_path), "%s/osm_data.img",
             data_dir ? data_dir : ".");

    memset(&bd_cfg, 0, sizeof(bd_cfg));
    bd_cfg.read_size   = 16;
    bd_cfg.prog_size   = 16;
    bd_cfg.erase_size  = BLOCK_SIZE;
    bd_cfg.erase_count = BLOCK_COUNT;

    memset(&cfg, 0, sizeof(cfg));
    cfg.context        = &bd;
    cfg.read           = lfs_filebd_read;
    cfg.prog           = lfs_filebd_prog;
    cfg.erase          = lfs_filebd_erase;
    cfg.sync           = lfs_filebd_sync;
    cfg.read_size      = 16;
    cfg.prog_size      = 16;
    cfg.block_size     = BLOCK_SIZE;
    cfg.block_count    = BLOCK_COUNT;
    cfg.cache_size     = 256;
    cfg.lookahead_size = 16;
    cfg.block_cycles   = 500;

    int err = lfs_filebd_create(&cfg, backing_path, &bd_cfg);
    if (err) return false;

    err = lfs_mount(&lfs, &cfg);
    if (err) {
        /* First use — format then mount */
        lfs_format(&lfs, &cfg);
        err = lfs_mount(&lfs, &cfg);
        if (err) {
            lfs_filebd_destroy(&cfg);
            return false;
        }
    }

    mounted = true;
    return true;
}

void hal_storage_deinit(void)
{
    if (!mounted) return;
    lfs_unmount(&lfs);
    lfs_filebd_destroy(&cfg);
    mounted = false;
}

lfs_t *hal_storage_get(void)
{
    return mounted ? &lfs : NULL;
}
