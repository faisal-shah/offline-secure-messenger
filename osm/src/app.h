#ifndef APP_H
#define APP_H

#include "lvgl.h"
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

/*====================
   CONSTANTS
====================*/
#define DEVICE_HOR_RES  320
#define DEVICE_VER_RES  240
#define MAX_CONTACTS    32
#define MAX_MESSAGES    256
#define MAX_NAME_LEN    64
#define MAX_TEXT_LEN    1024
#define MAX_CIPHER_LEN  2048
#define MAX_KEY_LEN     256

/*====================
   DATA TYPES
====================*/
typedef enum {
    CONTACT_PENDING_SENT,
    CONTACT_PENDING_RECEIVED,
    CONTACT_ESTABLISHED
} contact_status_t;

typedef struct {
    uint32_t id;
    char     name[MAX_NAME_LEN];
    contact_status_t status;
    char     public_key[MAX_KEY_LEN];
    char     shared_secret[MAX_KEY_LEN];
    uint32_t unread_count;
    time_t   created_at;
} contact_t;

typedef enum {
    MSG_SENT,
    MSG_RECEIVED
} msg_direction_t;

typedef struct {
    uint32_t        id;
    uint32_t        contact_id;
    msg_direction_t direction;
    char            plaintext[MAX_TEXT_LEN];
    char            ciphertext[MAX_CIPHER_LEN];
    time_t          timestamp;
} message_t;

/*====================
   SCREEN IDS
====================*/
typedef enum {
    SCR_HOME,
    SCR_CONTACTS,
    SCR_KEY_EXCHANGE,
    SCR_COMPOSE,
    SCR_INBOX,
    SCR_CONVERSATION,
    SCR_COUNT
} screen_id_t;

/*====================
   APP STATE
====================*/
typedef struct {
    lv_display_t *dev_disp;
    lv_indev_t   *mouse;
    lv_indev_t   *keyboard;
    lv_group_t   *dev_group;   /* Input group for device keyboard */
    bool          test_mode;
    bool          quit;

    /* Screens */
    lv_obj_t     *screens[SCR_COUNT];
    screen_id_t   current_screen;

    /* Navigation context */
    uint32_t      selected_contact_id;

    /* Data */
    contact_t     contacts[MAX_CONTACTS];
    uint32_t      contact_count;
    message_t     messages[MAX_MESSAGES];
    uint32_t      message_count;
    uint32_t      next_contact_id;
    uint32_t      next_message_id;
} app_state_t;

/* Global app state */
extern app_state_t g_app;

/*====================
   APP FUNCTIONS
====================*/
void app_init(lv_display_t *disp,
              lv_indev_t *mouse, lv_indev_t *kb,
              lv_group_t *dev_group, bool test_mode);

/* Log output to stderr (replaces I/O monitor) */
void app_log(const char *context, const char *data);
void app_deinit(void);
bool app_should_quit(void);
void app_navigate_to(screen_id_t scr);
void app_test_tick(void);

/* Screenshot helper */
void app_take_screenshot(const char *name);

#endif /* APP_H */
