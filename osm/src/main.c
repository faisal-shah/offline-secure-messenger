/**
 * Secure Communicator — UI Prototype
 * Entry point: LVGL + SDL2 initialization
 */

#include "lvgl.h"
#include "app.h"
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <stdlib.h>
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
    uint16_t port = TRANSPORT_DEFAULT_PORT;
    const char *name = "";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--test") == 0)
            test_mode = true;
        else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
            port = (uint16_t)atoi(argv[++i]);
        else if (strcmp(argv[i], "--name") == 0 && i + 1 < argc)
            name = argv[++i];
    }

#ifdef TRANSPORT_BLE
    printf("[OSM] Transport: BLE (BlueZ)\n");
#else
    printf("[OSM] Transport: TCP (port %d)\n", port);
#endif

    lv_init();
    lv_tick_set_cb(tick_get_cb);

    /* Device display — 320×240 (becomes default as first display) */
    lv_display_t *dev_disp = lv_sdl_window_create(DEVICE_HOR_RES, DEVICE_VER_RES);
    lv_sdl_window_set_zoom(dev_disp, SDL_ZOOM);
    lv_sdl_window_set_title(dev_disp,
        name[0] ? name : "Secure Communicator");

    /* Device input devices (dev_disp is already the default) */
    lv_indev_t *mouse = lv_sdl_mouse_create();
    lv_indev_t *kb    = lv_sdl_keyboard_create();

    /* Device input group — do NOT set as default to avoid
       auto-adding every widget from every screen/display */
    lv_group_t *dev_group = lv_group_create();
    lv_indev_set_group(kb, dev_group);

    /* Initialize the application */
    app_init(dev_disp, mouse, kb, dev_group, test_mode, port, name);

    /* Main loop */
    while (!app_should_quit()) {
        uint32_t sleep_ms = lv_timer_handler();
        app_transport_poll();
        if (test_mode) {
            app_test_tick();
        } else {
            app_poll_stdin();
        }
        usleep(sleep_ms * 1000);
    }

    app_deinit();
    lv_sdl_quit();
    lv_deinit();

    return 0;
}
