#ifndef APP_H
#define APP_H

#include "lvgl.h"
#include "crypto.h"
#include "transport/transport.h"
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
#define MAX_OUTBOX      32
#define MAX_PENDING_KEYS 8

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
    char     public_key[MAX_KEY_LEN];   /* peer's pubkey (base64) */
    uint32_t unread_count;
    time_t   created_at;
} contact_t;

typedef struct {
    char     pubkey_b64[MAX_KEY_LEN];
    time_t   received_at;
} pending_key_t;

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
    SCR_SETUP,
    SCR_HOME,
    SCR_CONTACTS,
    SCR_KEY_EXCHANGE,
    SCR_COMPOSE,
    SCR_INBOX,
    SCR_CONVERSATION,
    SCR_ASSIGN_KEY,
    SCR_COUNT
} screen_id_t;

/*====================
   OUTBOX (queued messages to send via transport)
====================*/
typedef struct {
    char     data[MAX_CIPHER_LEN];
    uint16_t char_uuid;
    uint8_t  msg_id[8];  /* SHA-512 first 8 bytes for ACK tracking */
    bool     acked;
    bool     sent;       /* true once sent (reset on CA reconnect) */
} outbox_entry_t;

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

    /* Device name (from --name CLI arg) */
    char              device_name[32];

    /* Identity (our keypair) */
    crypto_identity_t identity;

    /* Transport */
    transport_t   transport;
    uint16_t      transport_port;

    /* Outbound message queue */
    outbox_entry_t outbox[MAX_OUTBOX];
    uint32_t      outbox_count;

    /* Data */
    contact_t     contacts[MAX_CONTACTS];
    uint32_t      contact_count;
    message_t     messages[MAX_MESSAGES];
    uint32_t      message_count;
    uint32_t      next_contact_id;
    uint32_t      next_message_id;

    /* Pending inbound key exchanges (awaiting user assignment) */
    pending_key_t pending_keys[MAX_PENDING_KEYS];
    uint32_t      pending_key_count;
} app_state_t;

/* Global app state */
extern app_state_t g_app;

/*====================
   APP FUNCTIONS
====================*/
void app_init(lv_display_t *disp,
              lv_indev_t *mouse, lv_indev_t *kb,
              lv_group_t *dev_group, bool test_mode,
              uint16_t port, const char *name);

/* Log output to stderr (replaces I/O monitor) */
void app_log(const char *context, const char *data);
void app_deinit(void);
bool app_should_quit(void);
void app_navigate_to(screen_id_t scr);
void app_test_tick(void);

/* Transport: enqueue data to send to CA, flush queued messages */
void app_outbox_enqueue(uint16_t char_uuid, const char *data);
void app_outbox_flush(void);
void app_outbox_save(void);
void app_outbox_load(void);
void app_transport_poll(void);

/* Message envelope helpers */
#define MSG_PREFIX_KEY "OSM:KEY:"
#define MSG_PREFIX_MSG "OSM:MSG:"
void app_send_key_exchange(const char *pubkey_b64);
void app_send_encrypted_msg(const char *ciphertext_b64);

/* Pending key queue management */
bool app_pending_key_add(const char *pubkey_b64);
void app_pending_key_remove(uint32_t index);
void app_pending_keys_save(void);
void app_pending_keys_load(void);

/* Screenshot helper */
void app_take_screenshot(const char *name);

/* Non-blocking stdin command processing (for E2E test automation) */
void app_poll_stdin(void);

#endif /* APP_H */
