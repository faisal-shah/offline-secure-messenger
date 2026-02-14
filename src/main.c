/**
 * Secure Communicator — UI Prototype
 * Entry point: LVGL + SDL2 initialization
 */

#include "lvgl.h"
#include "app.h"
#include "io_monitor.h"
#include <unistd.h>
#include <time.h>
#include <string.h>

#define SDL_ZOOM        2

static uint32_t tick_get_cb(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int main(int argc, char *argv[])
{
    bool test_mode = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0) test_mode = true;
    }

    lv_init();
    lv_tick_set_cb(tick_get_cb);

    /* Device display — 320×240 */
    lv_display_t *dev_disp = lv_sdl_window_create(DEVICE_HOR_RES, DEVICE_VER_RES);
    lv_sdl_window_set_zoom(dev_disp, SDL_ZOOM);
    lv_sdl_window_set_title(dev_disp, "Secure Communicator");

    /* I/O Monitor display — separate window (skip in test mode) */
    lv_display_t *io_disp = NULL;
    if (!test_mode) {
        io_disp = lv_sdl_window_create(IO_MON_HOR_RES, IO_MON_VER_RES);
        lv_sdl_window_set_title(io_disp, "I/O Monitor");
        /* Create input devices for the monitor window */
        lv_sdl_mouse_create();
        lv_indev_t *io_kb = lv_sdl_keyboard_create();
        lv_group_t *io_group = lv_group_create();
        lv_indev_set_group(io_kb, io_group);
    }

    /* Ensure device display is default for input devices */
    lv_display_set_default(dev_disp);

    /* Input devices for device window */
    lv_indev_t *mouse = lv_sdl_mouse_create();
    lv_indev_t *kb    = lv_sdl_keyboard_create();

    /* Create input group so keyboard events reach focused widgets */
    lv_group_t *dev_group = lv_group_create();
    lv_group_set_default(dev_group);
    lv_indev_set_group(kb, dev_group);

    /* Initialize the application */
    app_init(dev_disp, io_disp, mouse, kb, test_mode);

    /* Main loop */
    while (!app_should_quit()) {
        uint32_t sleep_ms = lv_timer_handler();
        if (test_mode) {
            app_test_tick();
        }
        usleep(sleep_ms * 1000);
    }

    app_deinit();
    lv_sdl_quit();
    lv_deinit();

    return 0;
}
