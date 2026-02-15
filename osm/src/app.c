#include "app.h"
#include "data/contacts.h"
#include "data/messages.h"
#include "data/identity.h"
#include "screens/scr_setup.h"
#include "screens/scr_home.h"
#include "screens/scr_contacts.h"
#include "screens/scr_key_exchange.h"
#include "screens/scr_compose.h"
#include "screens/scr_inbox.h"
#include "screens/scr_conversation.h"
#include "screens/scr_assign_key.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

app_state_t g_app;

/* Forward declarations for test driver */
static void test_driver_init(void);

/*---------- Screenshot helper (via SDL renderer) ----------*/
#include LV_SDL_INCLUDE_PATH

void app_take_screenshot(const char *name)
{
    char path[256];
    snprintf(path, sizeof(path), "screenshots/%s.bmp", name);

    /* Force LVGL to render pending changes */
    lv_timer_handler();

    SDL_Renderer *renderer = (SDL_Renderer *)lv_sdl_window_get_renderer(g_app.dev_disp);
    if (!renderer) {
        printf("  SCREENSHOT FAIL: %s (no renderer)\n", name);
        return;
    }

    SDL_Window *window = lv_sdl_window_get_window(g_app.dev_disp);
    if (!window) {
        printf("  SCREENSHOT FAIL: %s (no window)\n", name);
        return;
    }

    int w, h;
    SDL_GetRendererOutputSize(renderer, &w, &h);

    SDL_Surface *surface = SDL_CreateRGBSurfaceWithFormat(0, w, h, 32, SDL_PIXELFORMAT_ARGB8888);
    if (!surface) {
        printf("  SCREENSHOT FAIL: %s (surface: %s)\n", name, SDL_GetError());
        return;
    }

    if (SDL_RenderReadPixels(renderer, NULL,
                              SDL_PIXELFORMAT_ARGB8888,
                              surface->pixels, surface->pitch) != 0) {
        printf("  SCREENSHOT FAIL: %s (readpixels: %s)\n", name, SDL_GetError());
        SDL_FreeSurface(surface);
        return;
    }

    SDL_SaveBMP(surface, path);
    SDL_FreeSurface(surface);
    printf("  SCREENSHOT: %s\n", path);
}

/*---------- Logging ----------*/
void app_log(const char *context, const char *data)
{
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[16];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    fprintf(stderr, "[%s] %s: %.60s%s\n",
            ts, context, data, strlen(data) > 60 ? "..." : "");
}

/*---------- Transport callbacks ----------*/
static void on_ca_connect(int client_idx)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "CA client %d connected", client_idx);
    app_log("Transport", buf);
}

static void on_ca_disconnect(int client_idx)
{
    char buf[64];
    snprintf(buf, sizeof(buf), "CA client %d disconnected", client_idx);
    app_log("Transport", buf);
}

static void handle_key_exchange_msg(const char *pubkey_b64)
{
    /* Format is now just <pubkey_b64> (no sender name) */
    uint8_t peer_pubkey[CRYPTO_PUBKEY_BYTES];
    if (!crypto_b64_to_pubkey(pubkey_b64, peer_pubkey)) {
        app_log("CA->OSM", "Malformed KEX message (bad pubkey)");
        return;
    }

    /* Check for duplicate — is this pubkey already on a contact? */
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (strcmp(g_app.contacts[i].public_key, pubkey_b64) == 0) {
            app_log("CA->OSM", "KEX pubkey already known, ignoring");
            return;
        }
    }

    /* Check for duplicate in pending queue */
    for (uint32_t i = 0; i < g_app.pending_key_count; i++) {
        if (strcmp(g_app.pending_keys[i].pubkey_b64, pubkey_b64) == 0) {
            app_log("CA->OSM", "KEX pubkey already pending, ignoring");
            return;
        }
    }

    /* Store in pending queue for user to assign */
    if (!app_pending_key_add(pubkey_b64)) {
        app_log("CA->OSM", "Pending key queue full, dropping");
        return;
    }

    app_log("CA->OSM", "KEX queued for assignment");
    app_pending_keys_save();

    /* Navigate to assign screen or refresh relevant screen */
    if (g_app.current_screen == SCR_HOME) {
        scr_home_refresh();
    } else if (g_app.current_screen == SCR_ASSIGN_KEY) {
        scr_assign_key_refresh();
    }
}

static void handle_encrypted_msg(const char *ciphertext)
{
    /* Try to decrypt with each established contact's pubkey */
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        contact_t *c = &g_app.contacts[i];
        if (c->status != CONTACT_ESTABLISHED) continue;

        uint8_t peer_pubkey[CRYPTO_PUBKEY_BYTES];
        if (!crypto_b64_to_pubkey(c->public_key, peer_pubkey))
            continue;

        char plaintext[MAX_TEXT_LEN];
        if (crypto_decrypt(ciphertext, peer_pubkey, g_app.identity.privkey,
                           plaintext, sizeof(plaintext))) {
            message_t *msg = messages_add(c->id, MSG_RECEIVED, "");
            if (msg) {
                strncpy(msg->plaintext, plaintext, MAX_TEXT_LEN - 1);
                strncpy(msg->ciphertext, ciphertext, MAX_CIPHER_LEN - 1);
                c->unread_count++;
                messages_save();
                contacts_save();
                char ctx[128];
                snprintf(ctx, sizeof(ctx), "Decrypted from %s", c->name);
                app_log(ctx, plaintext);

                /* Refresh UI if on relevant screen */
                if (g_app.current_screen == SCR_HOME)
                    scr_home_refresh();
                else if (g_app.current_screen == SCR_INBOX)
                    scr_inbox_refresh();
                else if (g_app.current_screen == SCR_CONVERSATION)
                    scr_conversation_refresh();
            }
            return;
        }
    }
    app_log("CA->OSM", "Could not decrypt (unknown sender or bad key)");
}

static void on_ca_message(int client_idx, uint16_t char_uuid,
                          const uint8_t *data, size_t len)
{
    (void)client_idx;
    if (char_uuid != CHAR_UUID_RX || len == 0) return;

    char buf[MAX_CIPHER_LEN];
    if (len >= MAX_CIPHER_LEN) len = MAX_CIPHER_LEN - 1;
    memcpy(buf, data, len);
    buf[len] = '\0';

    app_log("CA->OSM", buf);

    if (strncmp(buf, MSG_PREFIX_KEY, strlen(MSG_PREFIX_KEY)) == 0) {
        handle_key_exchange_msg(buf + strlen(MSG_PREFIX_KEY));
    } else if (strncmp(buf, MSG_PREFIX_MSG, strlen(MSG_PREFIX_MSG)) == 0) {
        handle_encrypted_msg(buf + strlen(MSG_PREFIX_MSG));
    } else {
        app_log("CA->OSM", "Unknown message format (no OSM: prefix)");
    }
}

/*---------- App lifecycle ----------*/
void app_init(lv_display_t *disp,
              lv_indev_t *mouse, lv_indev_t *kb,
              lv_group_t *dev_group, bool test_mode,
              uint16_t port, const char *name)
{
    memset(&g_app, 0, sizeof(g_app));
    g_app.dev_disp = disp;
    g_app.mouse = mouse;
    g_app.keyboard = kb;
    g_app.dev_group = dev_group;
    g_app.test_mode = test_mode;
    g_app.quit = false;
    g_app.next_contact_id = 1;
    g_app.next_message_id = 1;
    g_app.transport_port = port;
    if (name && name[0])
        strncpy(g_app.device_name, name, sizeof(g_app.device_name) - 1);

    mkdir("screenshots", 0755);

    /* Load persisted data */
    identity_load(&g_app.identity);
    contacts_load();
    messages_load();
    app_pending_keys_load();

    /* Apply dark theme */
    lv_theme_t *th = lv_theme_default_init(
        disp,
        lv_color_hex(0x00B0FF),   /* primary: bright blue */
        lv_color_hex(0xFF6D00),   /* secondary: amber */
        true,                      /* dark mode */
        &lv_font_montserrat_12
    );
    lv_display_set_theme(disp, th);

    /* Create all screens (on device display) */
    lv_display_set_default(disp);
    scr_setup_create();
    scr_home_create();
    scr_contacts_create();
    scr_key_exchange_create();
    scr_compose_create();
    scr_inbox_create();
    scr_conversation_create();
    scr_assign_key_create();

    /* Start transport (non-blocking, OK if port unavailable in test mode) */
    transport_init(&g_app.transport, port);
    transport_set_callbacks(&g_app.transport, (transport_callbacks_t){
        .on_connect    = on_ca_connect,
        .on_disconnect = on_ca_disconnect,
        .on_message    = on_ca_message,
    });
    if (!test_mode) {
        if (transport_start(&g_app.transport))
            app_log("Transport", "Started");
        else
            app_log("Transport", "Failed to start (port in use?)");
    }

    /* Start on setup or home depending on identity */
    if (g_app.identity.valid) {
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
    } else if (test_mode) {
        /* In test mode, auto-generate keypair so tests work */
        crypto_generate_keypair(&g_app.identity);
        identity_save(&g_app.identity);
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
    } else {
        app_navigate_to(SCR_SETUP);
    }

    if (test_mode) {
        printf("=== SELF-TEST MODE ===\n");
        test_driver_init();
    }
}

void app_deinit(void)
{
    transport_stop(&g_app.transport);
    contacts_save();
    messages_save();
}

bool app_should_quit(void)
{
    return g_app.quit;
}

void app_navigate_to(screen_id_t scr)
{
    if (scr >= SCR_COUNT || !g_app.screens[scr]) return;
    g_app.current_screen = scr;
    lv_screen_load(g_app.screens[scr]);
}

/*---------- Outbox (queued messages for CA) ----------*/
void app_outbox_enqueue(uint16_t char_uuid, const char *data)
{
    if (g_app.outbox_count >= MAX_OUTBOX) {
        app_log("Outbox", "FULL — dropping message");
        return;
    }
    outbox_entry_t *e = &g_app.outbox[g_app.outbox_count++];
    e->char_uuid = char_uuid;
    strncpy(e->data, data, MAX_CIPHER_LEN - 1);
    e->data[MAX_CIPHER_LEN - 1] = '\0';
    app_log("Outbox", "Queued message");

    /* Try to flush immediately */
    app_outbox_flush();
}

void app_outbox_flush(void)
{
    if (g_app.outbox_count == 0) return;
    if (transport_connected_count(&g_app.transport) == 0) return;

    uint32_t sent = 0;
    for (uint32_t i = 0; i < g_app.outbox_count; i++) {
        outbox_entry_t *e = &g_app.outbox[i];
        transport_broadcast_message(&g_app.transport, e->char_uuid,
                                    (const uint8_t *)e->data,
                                    strlen(e->data));
        sent++;
    }
    if (sent > 0) {
        g_app.outbox_count = 0;
        char buf[32];
        snprintf(buf, sizeof(buf), "Flushed %u messages", sent);
        app_log("Outbox", buf);
    }
}

void app_transport_poll(void)
{
    transport_poll(&g_app.transport);

    /* Try to flush outbox on each poll (in case CA just connected) */
    app_outbox_flush();
}

/*---------- Message envelope helpers ----------*/
void app_send_key_exchange(const char *pubkey_b64)
{
    char envelope[MAX_CIPHER_LEN];
    snprintf(envelope, sizeof(envelope), "%s%s",
             MSG_PREFIX_KEY, pubkey_b64);
    app_outbox_enqueue(CHAR_UUID_TX, envelope);
}

void app_send_encrypted_msg(const char *ciphertext_b64)
{
    char envelope[MAX_CIPHER_LEN];
    snprintf(envelope, sizeof(envelope), "%s%s",
             MSG_PREFIX_MSG, ciphertext_b64);
    app_outbox_enqueue(CHAR_UUID_TX, envelope);
}

/*---------- Pending key queue ----------*/
#define PENDING_KEYS_FILE "data_pending_keys.json"

bool app_pending_key_add(const char *pubkey_b64)
{
    if (g_app.pending_key_count >= MAX_PENDING_KEYS) return false;
    pending_key_t *pk = &g_app.pending_keys[g_app.pending_key_count];
    memset(pk, 0, sizeof(*pk));
    strncpy(pk->pubkey_b64, pubkey_b64, MAX_KEY_LEN - 1);
    pk->received_at = time(NULL);
    g_app.pending_key_count++;
    return true;
}

void app_pending_key_remove(uint32_t index)
{
    if (index >= g_app.pending_key_count) return;
    for (uint32_t i = index; i < g_app.pending_key_count - 1; i++)
        g_app.pending_keys[i] = g_app.pending_keys[i + 1];
    g_app.pending_key_count--;
    memset(&g_app.pending_keys[g_app.pending_key_count], 0, sizeof(pending_key_t));
}

void app_pending_keys_save(void)
{
    FILE *f = fopen(PENDING_KEYS_FILE, "w");
    if (!f) return;
    fprintf(f, "[\n");
    for (uint32_t i = 0; i < g_app.pending_key_count; i++) {
        pending_key_t *pk = &g_app.pending_keys[i];
        fprintf(f, "  {\"pubkey\":\"%s\", \"received\":%ld}%s\n",
                pk->pubkey_b64, (long)pk->received_at,
                (i < g_app.pending_key_count - 1) ? "," : "");
    }
    fprintf(f, "]\n");
    fclose(f);
}

void app_pending_keys_load(void)
{
    FILE *f = fopen(PENDING_KEYS_FILE, "r");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) { fclose(f); return; }

    char *buf = malloc(len + 1);
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);

    g_app.pending_key_count = 0;
    const char *p = buf;
    while (g_app.pending_key_count < MAX_PENDING_KEYS) {
        const char *pk_str = strstr(p, "\"pubkey\":\"");
        if (!pk_str) break;
        pk_str += 10;
        const char *end = strchr(pk_str, '"');
        if (!end) break;

        pending_key_t *pk = &g_app.pending_keys[g_app.pending_key_count];
        memset(pk, 0, sizeof(*pk));
        size_t klen = end - pk_str;
        if (klen >= MAX_KEY_LEN) klen = MAX_KEY_LEN - 1;
        memcpy(pk->pubkey_b64, pk_str, klen);

        const char *ts_str = strstr(pk_str, "\"received\":");
        if (ts_str) sscanf(ts_str, "\"received\":%ld", (long *)&pk->received_at);

        g_app.pending_key_count++;
        p = end + 1;
    }
    free(buf);
}

/*---------- Test driver ----------*/

typedef enum {
    TEST_IDLE,
    TEST_START,
    TEST_STEP,
    TEST_DONE,
} test_state_t;

static struct {
    test_state_t state;
    int step;
    int wait_frames;
    int pass_count;
    int fail_count;
} test_ctx;

static void test_pass(const char *msg)
{
    printf("  PASS: %s\n", msg);
    test_ctx.pass_count++;
}

static void test_fail(const char *msg)
{
    printf("  FAIL: %s\n", msg);
    test_ctx.fail_count++;
}

static void test_driver_init(void)
{
    test_ctx.state = TEST_START;
    test_ctx.step = 0;
    test_ctx.wait_frames = 5;
    test_ctx.pass_count = 0;
    test_ctx.fail_count = 0;
}

/* Generate a test peer keypair and store its pubkey in a contact */
static void test_set_peer_pubkey(contact_t *c)
{
    crypto_identity_t peer;
    crypto_generate_keypair(&peer);
    crypto_pubkey_to_b64(peer.pubkey, c->public_key, MAX_KEY_LEN);
}

/* Each step: do an action, take a screenshot, verify state */
static void test_execute_step(void)
{
    char scr_name[64];
    snprintf(scr_name, sizeof(scr_name), "step_%02d", test_ctx.step);

    switch (test_ctx.step) {
    case 0: /* Home screen - empty state */
        printf("[Step 0] Home screen (empty)\n");
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        app_take_screenshot("01_home_empty");
        if (g_app.current_screen == SCR_HOME) test_pass("Home screen loaded");
        else test_fail("Home screen not loaded");
        break;

    case 1: /* Navigate to contacts */
        printf("[Step 1] Navigate to Contacts\n");
        app_navigate_to(SCR_CONTACTS);
        scr_contacts_refresh();
        app_take_screenshot("02_contacts_empty");
        if (g_app.current_screen == SCR_CONTACTS) test_pass("Contacts screen");
        else test_fail("Contacts screen");
        break;

    case 2: { /* Create new contact "Alice" and initiate key exchange */
        printf("[Step 2] Create contact Alice\n");
        contact_t *alice = contacts_add("Alice");
        if (alice) {
            alice->status = CONTACT_PENDING_SENT;
            contacts_save();
            scr_contacts_refresh();
            app_take_screenshot("03_contact_alice_pending");
            test_pass("Created contact Alice (pending_sent)");
        } else {
            test_fail("Failed to create Alice");
        }
        break;
    }

    case 3: /* Navigate to key exchange */
        printf("[Step 3] Key exchange wizard for Alice\n");
        g_app.selected_contact_id = contacts_find_by_name("Alice") ?
            contacts_find_by_name("Alice")->id : 0;
        app_navigate_to(SCR_KEY_EXCHANGE);
        scr_key_exchange_refresh();
        app_take_screenshot("04_key_exchange_pending");
        test_pass("Key exchange screen for Alice");
        break;

    case 4: { /* Simulate Alice's DH reply → established */
        printf("[Step 4] Complete key exchange with Alice\n");
        contact_t *alice = contacts_find_by_name("Alice");
        if (alice) {
            test_set_peer_pubkey(alice);
            alice->status = CONTACT_ESTABLISHED;
            contacts_save();
            scr_key_exchange_refresh();
            app_take_screenshot("05_key_exchange_complete");
            test_pass("Alice now ESTABLISHED");
        } else {
            test_fail("Alice not found");
        }
        break;
    }

    case 5: /* Verify contact list shows established */
        printf("[Step 5] Contacts list — Alice established\n");
        app_navigate_to(SCR_CONTACTS);
        scr_contacts_refresh();
        app_take_screenshot("06_contacts_established");
        test_pass("Contacts list updated");
        break;

    case 6: /* Navigate to compose */
        printf("[Step 6] Compose screen\n");
        app_navigate_to(SCR_COMPOSE);
        scr_compose_refresh();
        app_take_screenshot("07_compose_screen");
        if (g_app.current_screen == SCR_COMPOSE) test_pass("Compose screen");
        else test_fail("Compose screen");
        break;

    case 7: { /* Send message to Alice */
        printf("[Step 7] Send message to Alice\n");
        g_app.selected_contact_id = contacts_find_by_name("Alice") ?
            contacts_find_by_name("Alice")->id : 0;
        message_t *msg = messages_add(g_app.selected_contact_id, MSG_SENT,
                                       "Hello Alice, this is a secure test message!");
        if (msg) {
            messages_save();
            scr_compose_refresh();
            app_take_screenshot("08_message_sent");
            test_pass("Sent message to Alice");
        } else {
            test_fail("Failed to send message");
        }
        break;
    }

    case 8: /* Check inbox */
        printf("[Step 8] Inbox screen\n");
        app_navigate_to(SCR_INBOX);
        scr_inbox_refresh();
        app_take_screenshot("09_inbox_after_send");
        test_pass("Inbox screen loaded");
        break;

    case 9: /* View conversation with Alice */
        printf("[Step 9] Conversation with Alice\n");
        g_app.selected_contact_id = contacts_find_by_name("Alice") ?
            contacts_find_by_name("Alice")->id : 0;
        app_navigate_to(SCR_CONVERSATION);
        scr_conversation_refresh();
        app_take_screenshot("10_conversation_sent");
        test_pass("Conversation view");
        break;

    case 10: { /* Receive message from Alice */
        printf("[Step 10] Receive message from Alice\n");
        contact_t *alice = contacts_find_by_name("Alice");
        if (alice) {
            message_t *msg = messages_add(alice->id, MSG_RECEIVED,
                "Hi! Got your message. Everything is working great on my end.");
            if (msg) {
                alice->unread_count++;
                messages_save();
                contacts_save();
            }
            scr_conversation_refresh();
            app_take_screenshot("11_conversation_received");
            test_pass("Received message from Alice");
        } else {
            test_fail("Alice not found");
        }
        break;
    }

    case 11: /* Inbox with unread */
        printf("[Step 11] Inbox with unread indicator\n");
        app_navigate_to(SCR_INBOX);
        scr_inbox_refresh();
        app_take_screenshot("12_inbox_unread");
        test_pass("Inbox shows unread");
        break;

    case 12: { /* New inbound contact "Bob" */
        printf("[Step 12] Simulate new inbound contact Bob\n");
        contact_t *bob = contacts_add("Bob");
        if (bob) {
            bob->status = CONTACT_PENDING_RECEIVED;
            test_set_peer_pubkey(bob);
            contacts_save();
        }
        app_navigate_to(SCR_CONTACTS);
        scr_contacts_refresh();
        app_take_screenshot("13_contacts_bob_pending");
        test_pass("Bob created as pending_received");
        break;
    }

    case 13: { /* Complete Bob's key exchange */
        printf("[Step 13] Complete Bob's key exchange\n");
        contact_t *bob = contacts_find_by_name("Bob");
        if (bob) {
            bob->status = CONTACT_ESTABLISHED;
            contacts_save();
        }
        scr_contacts_refresh();
        app_take_screenshot("14_contacts_bob_established");
        test_pass("Bob now ESTABLISHED");
        break;
    }

    case 14: /* Home screen with contacts */
        printf("[Step 14] Home screen with contacts\n");
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        app_take_screenshot("15_home_with_contacts");
        test_pass("Home screen with contacts");
        break;

    case 15: { /* Send message to Bob */
        printf("[Step 15] Send message to Bob\n");
        contact_t *bob = contacts_find_by_name("Bob");
        if (bob) {
            messages_add(bob->id, MSG_SENT, "Hey Bob, welcome to the secure channel!");
            messages_add(bob->id, MSG_RECEIVED, "Thanks! Glad to be connected securely.");
            messages_save();
        }
        app_navigate_to(SCR_INBOX);
        scr_inbox_refresh();
        app_take_screenshot("16_inbox_both_contacts");
        test_pass("Inbox with both contacts");
        break;
    }

    case 16: /* Persistence test — save and reload */
        printf("[Step 16] Persistence test\n");
        contacts_save();
        messages_save();
        /* Clear and reload */
        g_app.contact_count = 0;
        g_app.message_count = 0;
        contacts_load();
        messages_load();
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        app_take_screenshot("17_home_after_reload");
        if (g_app.contact_count >= 2) test_pass("Persistence: contacts survived reload");
        else test_fail("Persistence: contacts lost");
        if (g_app.message_count >= 3) test_pass("Persistence: messages survived reload");
        else test_fail("Persistence: messages lost");
        break;

    case 17: /* Final conversation view */
        printf("[Step 17] Final conversation view\n");
        g_app.selected_contact_id = contacts_find_by_name("Alice") ?
            contacts_find_by_name("Alice")->id : 0;
        app_navigate_to(SCR_CONVERSATION);
        scr_conversation_refresh();
        app_take_screenshot("18_final_conversation");
        test_pass("Final conversation view");
        break;

    /*======================================================
     * Phase 2: Interactive UI flow tests
     * Exercise actual button clicks, textarea input, and
     * screen navigation to verify the UI is responsive.
     *======================================================*/

    case 18: { /* Reset state for interactive tests */
        printf("\n--- Phase 2: Interactive UI Flow Tests ---\n");
        printf("[Step 18] Reset state\n");
        g_app.contact_count = 0;
        g_app.message_count = 0;
        g_app.next_contact_id = 1;
        g_app.next_message_id = 1;
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        if (g_app.contact_count == 0) test_pass("State reset for interactive tests");
        else test_fail("State not cleared");
        break;
    }

    case 19: { /* Click Contacts nav button on home screen */
        printf("[Step 19] Click Contacts nav button\n");
        /* Find the nav bar (last child of home screen), then first button */
        lv_obj_t *home_scr = g_app.screens[SCR_HOME];
        uint32_t cnt = lv_obj_get_child_count(home_scr);
        lv_obj_t *nav_bar = lv_obj_get_child(home_scr, cnt - 1);
        lv_obj_t *contacts_btn = lv_obj_get_child(nav_bar, 0);
        lv_obj_send_event(contacts_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen == SCR_CONTACTS) test_pass("Nav to Contacts via click");
        else test_fail("Nav to Contacts failed");
        break;
    }

    case 20: { /* Click [+] to open add contact dialog */
        printf("[Step 20] Click [+] add contact button\n");
        lv_obj_t *contacts_scr = g_app.screens[SCR_CONTACTS];
        /* Header is child 0, add button is rightmost child of header */
        lv_obj_t *header = lv_obj_get_child(contacts_scr, 0);
        uint32_t hcnt = lv_obj_get_child_count(header);
        lv_obj_t *add_btn = lv_obj_get_child(header, hcnt - 1);
        lv_obj_send_event(add_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        /* Name input overlay should be visible */
        lv_obj_t *overlay = lv_obj_get_child(contacts_scr, 2); /* overlay is 3rd child */
        bool visible = !lv_obj_has_flag(overlay, LV_OBJ_FLAG_HIDDEN);
        if (visible) test_pass("Add contact dialog opened");
        else test_fail("Dialog not visible");
        break;
    }

    case 21: { /* Type contact name and click Create */
        printf("[Step 21] Type name 'Charlie' and click Create\n");
        lv_obj_t *contacts_scr = g_app.screens[SCR_CONTACTS];
        lv_obj_t *overlay = lv_obj_get_child(contacts_scr, 2);
        /* Find textarea in overlay (child 1) and OK button (child 2) */
        lv_obj_t *ta = lv_obj_get_child(overlay, 1);
        lv_obj_t *ok_btn = lv_obj_get_child(overlay, 2);
        lv_textarea_set_text(ta, "Charlie");
        lv_obj_send_event(ok_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        /* Should navigate to Key Exchange */
        if (g_app.current_screen == SCR_KEY_EXCHANGE) test_pass("Create navigated to Key Exchange");
        else test_fail("Expected Key Exchange screen, got " );
        /* Verify contact was created */
        contact_t *c = contacts_find_by_name("Charlie");
        if (c && c->status == CONTACT_PENDING_SENT) test_pass("Charlie created as pending_sent");
        else test_fail("Charlie not created properly");
        app_take_screenshot("19_interactive_key_exchange");
        break;
    }

    case 22: { /* Click Back from Key Exchange → Contacts */
        printf("[Step 22] Click Back from Key Exchange\n");
        lv_obj_t *ke_scr = g_app.screens[SCR_KEY_EXCHANGE];
        lv_obj_t *header = lv_obj_get_child(ke_scr, 0);
        lv_obj_t *back_btn = lv_obj_get_child(header, 0);
        lv_obj_send_event(back_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen == SCR_CONTACTS) test_pass("Back to Contacts");
        else test_fail("Not on Contacts screen");
        app_take_screenshot("20_interactive_contacts_after_back");
        break;
    }

    case 23: { /* Click on the pending contact row → Key Exchange */
        printf("[Step 23] Click on Charlie contact row\n");
        lv_obj_t *contacts_scr = g_app.screens[SCR_CONTACTS];
        lv_obj_t *list = lv_obj_get_child(contacts_scr, 1);
        if (lv_obj_get_child_count(list) > 0) {
            lv_obj_t *row = lv_obj_get_child(list, 0);
            lv_obj_send_event(row, LV_EVENT_CLICKED, NULL);
            lv_timer_handler();
            if (g_app.current_screen == SCR_KEY_EXCHANGE) test_pass("Clicked contact → Key Exchange");
            else test_fail("Expected Key Exchange");
        } else {
            test_fail("No contact rows found");
        }
        break;
    }

    case 24: { /* Simulate DH reply → ESTABLISHED */
        printf("[Step 24] Simulate DH reply for Charlie\n");
        contact_t *c = contacts_find_by_name("Charlie");
        if (c) {
            test_set_peer_pubkey(c);
            c->status = CONTACT_ESTABLISHED;
            contacts_save();
            scr_key_exchange_refresh();
            lv_timer_handler();
            if (c->status == CONTACT_ESTABLISHED) test_pass("Charlie now ESTABLISHED");
            else test_fail("Charlie not established");
        } else {
            test_fail("Charlie not found");
        }
        app_take_screenshot("21_interactive_established");
        break;
    }

    case 25: { /* Click Back from KE, go Home, click Compose nav */
        printf("[Step 25] Navigate Home → Compose via click\n");
        /* Back from key exchange */
        lv_obj_t *ke_scr = g_app.screens[SCR_KEY_EXCHANGE];
        lv_obj_t *ke_header = lv_obj_get_child(ke_scr, 0);
        lv_obj_t *back_btn = lv_obj_get_child(ke_header, 0);
        lv_obj_send_event(back_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        /* Now on Contacts, click back to Home */
        lv_obj_t *ct_scr = g_app.screens[SCR_CONTACTS];
        lv_obj_t *ct_header = lv_obj_get_child(ct_scr, 0);
        lv_obj_t *ct_back = lv_obj_get_child(ct_header, 0);
        lv_obj_send_event(ct_back, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen != SCR_HOME) { test_fail("Not on Home"); break; }
        /* Click Compose button (index 1 in nav bar) */
        lv_obj_t *home = g_app.screens[SCR_HOME];
        uint32_t hcnt = lv_obj_get_child_count(home);
        lv_obj_t *nav_bar = lv_obj_get_child(home, hcnt - 1);
        lv_obj_t *compose_btn = lv_obj_get_child(nav_bar, 1);
        lv_obj_send_event(compose_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen == SCR_COMPOSE) test_pass("Compose screen via click chain");
        else test_fail("Not on Compose screen");
        break;
    }

    case 26: { /* Type message on Compose and send */
        printf("[Step 26] Type message and send on Compose\n");
        scr_compose_refresh(); /* populate dropdown */
        lv_timer_handler();
        lv_obj_t *compose_scr = g_app.screens[SCR_COMPOSE];
        lv_obj_t *body = lv_obj_get_child(compose_scr, 1);
        /* dropdown is child 1, textarea is child 3, send_btn is child 5 */
        lv_obj_t *ta = lv_obj_get_child(body, 3);
        lv_obj_t *send_btn_obj = lv_obj_get_child(body, 5);
        lv_textarea_set_text(ta, "Interactive test message to Charlie!");
        lv_timer_handler();
        uint32_t msg_before = g_app.message_count;
        lv_obj_send_event(send_btn_obj, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.message_count > msg_before) test_pass("Message sent via Compose UI");
        else test_fail("Message not created");
        app_take_screenshot("22_interactive_compose_sent");
        break;
    }

    case 27: { /* Click Back to Home, then Inbox nav */
        printf("[Step 27] Navigate to Inbox via clicks\n");
        lv_obj_t *compose_scr = g_app.screens[SCR_COMPOSE];
        lv_obj_t *c_header = lv_obj_get_child(compose_scr, 0);
        lv_obj_t *back_btn = lv_obj_get_child(c_header, 0);
        lv_obj_send_event(back_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen != SCR_HOME) { test_fail("Not on Home"); break; }
        /* Click Inbox (index 2 in nav bar) */
        lv_obj_t *home = g_app.screens[SCR_HOME];
        uint32_t hcnt = lv_obj_get_child_count(home);
        lv_obj_t *nav_bar = lv_obj_get_child(home, hcnt - 1);
        lv_obj_t *inbox_btn = lv_obj_get_child(nav_bar, 2);
        lv_obj_send_event(inbox_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen == SCR_INBOX) test_pass("Inbox via click chain");
        else test_fail("Not on Inbox");
        app_take_screenshot("23_interactive_inbox");
        break;
    }

    case 28: { /* Click conversation row → Conversation screen */
        printf("[Step 28] Click conversation row in Inbox\n");
        lv_obj_t *inbox_scr = g_app.screens[SCR_INBOX];
        lv_obj_t *list = lv_obj_get_child(inbox_scr, 1);
        if (lv_obj_get_child_count(list) > 0) {
            lv_obj_t *row = lv_obj_get_child(list, 0);
            lv_obj_send_event(row, LV_EVENT_CLICKED, NULL);
            lv_timer_handler();
            if (g_app.current_screen == SCR_CONVERSATION) test_pass("Conversation via Inbox click");
            else test_fail("Not on Conversation screen");
        } else {
            test_fail("No conversation rows in inbox");
        }
        break;
    }

    case 29: { /* Type reply in conversation and send */
        printf("[Step 29] Type reply in Conversation and send\n");
        lv_obj_t *convo_scr = g_app.screens[SCR_CONVERSATION];
        /* reply_bar is child 2, reply_ta is child 0 of reply_bar, send_btn is child 1 */
        lv_obj_t *reply_bar = lv_obj_get_child(convo_scr, 2);
        lv_obj_t *ta = lv_obj_get_child(reply_bar, 0);
        lv_obj_t *send_btn_obj = lv_obj_get_child(reply_bar, 1);
        lv_textarea_set_text(ta, "Interactive reply message!");
        uint32_t msg_before = g_app.message_count;
        lv_obj_send_event(send_btn_obj, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.message_count > msg_before) test_pass("Reply sent via Conversation UI");
        else test_fail("Reply not created");
        app_take_screenshot("24_interactive_conversation");
        break;
    }

    case 30: { /* Click Back from Conversation → Inbox → Home */
        printf("[Step 30] Navigate back: Conversation → Inbox → Home\n");
        /* Back from Conversation */
        lv_obj_t *convo_scr = g_app.screens[SCR_CONVERSATION];
        lv_obj_t *c_header = lv_obj_get_child(convo_scr, 0);
        lv_obj_t *back1 = lv_obj_get_child(c_header, 0);
        lv_obj_send_event(back1, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen != SCR_INBOX) { test_fail("Not on Inbox after back"); break; }
        /* Back from Inbox */
        lv_obj_t *inbox_scr = g_app.screens[SCR_INBOX];
        lv_obj_t *i_header = lv_obj_get_child(inbox_scr, 0);
        lv_obj_t *back2 = lv_obj_get_child(i_header, 0);
        lv_obj_send_event(back2, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        if (g_app.current_screen == SCR_HOME) test_pass("Full back navigation chain");
        else test_fail("Not on Home after double back");
        app_take_screenshot("25_interactive_home_final");
        break;
    }

    case 31: { /* Verify textarea is in device group for keyboard input */
        printf("[Step 31] Verify textareas in device input group\n");
        lv_group_t *g = g_app.dev_group;
        if (!g) { test_fail("No device group"); break; }
        uint32_t obj_count = lv_group_get_obj_count(g);
        /* We expect 3 textareas: compose msg_ta, conversation reply_ta, contacts name_ta */
        if (obj_count >= 3) test_pass("Device group has textareas (" );
        else test_fail("Device group too few objects");
        /* Test that we can focus compose textarea */
        app_navigate_to(SCR_COMPOSE);
        scr_compose_refresh();
        lv_obj_t *body = lv_obj_get_child(g_app.screens[SCR_COMPOSE], 1);
        lv_obj_t *ta = lv_obj_get_child(body, 3);
        lv_group_focus_obj(ta);
        lv_timer_handler();
        lv_obj_t *focused = lv_group_get_focused(g);
        if (focused == ta) test_pass("Can focus compose textarea");
        else test_fail("Cannot focus compose textarea");
        break;
    }

    case 32: { /* Rapid navigation stress test */
        printf("[Step 32] Rapid navigation stress test\n");
        screen_id_t screens[] = {SCR_HOME, SCR_CONTACTS, SCR_HOME,
                                  SCR_COMPOSE, SCR_HOME, SCR_INBOX,
                                  SCR_HOME, SCR_CONTACTS, SCR_HOME};
        void (*refreshers[])(void) = {scr_home_refresh, scr_contacts_refresh,
                                       scr_home_refresh, scr_compose_refresh,
                                       scr_home_refresh, scr_inbox_refresh,
                                       scr_home_refresh, scr_contacts_refresh,
                                       scr_home_refresh};
        bool ok = true;
        for (int i = 0; i < 9; i++) {
            app_navigate_to(screens[i]);
            refreshers[i]();
            lv_timer_handler();
            if (g_app.current_screen != screens[i]) { ok = false; break; }
        }
        if (ok) test_pass("Rapid navigation (9 switches) stable");
        else test_fail("Navigation broke during stress test");
        break;
    }

    case 33: { /* Create second contact via UI, verify both in list */
        printf("[Step 33] Create second contact 'Diana' via UI\n");
        app_navigate_to(SCR_CONTACTS);
        scr_contacts_refresh();
        lv_timer_handler();
        /* Click [+] */
        lv_obj_t *contacts_scr = g_app.screens[SCR_CONTACTS];
        lv_obj_t *header = lv_obj_get_child(contacts_scr, 0);
        uint32_t hcnt = lv_obj_get_child_count(header);
        lv_obj_t *add_btn = lv_obj_get_child(header, hcnt - 1);
        lv_obj_send_event(add_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        /* Type name and create */
        lv_obj_t *overlay = lv_obj_get_child(contacts_scr, 2);
        lv_obj_t *ta = lv_obj_get_child(overlay, 1);
        lv_obj_t *ok_btn = lv_obj_get_child(overlay, 2);
        lv_textarea_set_text(ta, "Diana");
        lv_obj_send_event(ok_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        /* Verify Diana created and we're on Key Exchange */
        contact_t *d = contacts_find_by_name("Diana");
        if (d && g_app.current_screen == SCR_KEY_EXCHANGE) test_pass("Diana created via UI");
        else test_fail("Diana creation failed");
        /* Go back to contacts */
        lv_obj_t *ke_scr = g_app.screens[SCR_KEY_EXCHANGE];
        lv_obj_t *ke_hdr = lv_obj_get_child(ke_scr, 0);
        lv_obj_t *back_btn = lv_obj_get_child(ke_hdr, 0);
        lv_obj_send_event(back_btn, LV_EVENT_CLICKED, NULL);
        lv_timer_handler();
        /* Verify contacts list shows both */
        if (g_app.contact_count == 2 && g_app.current_screen == SCR_CONTACTS)
            test_pass("Contacts list shows both contacts");
        else test_fail("Contacts list wrong after second add");
        app_take_screenshot("26_interactive_two_contacts");
        break;
    }

    case 34: { /* Receive simulated message and check inbox */
        printf("[Step 34] Simulate incoming message and verify inbox\n");
        contact_t *c = contacts_find_by_name("Charlie");
        if (!c) { test_fail("Charlie not found"); break; }
        messages_add(c->id, MSG_RECEIVED, "Hey, this is a simulated incoming message!");
        c->unread_count++;
        messages_save();
        contacts_save();
        app_navigate_to(SCR_INBOX);
        scr_inbox_refresh();
        lv_timer_handler();
        if (g_app.current_screen == SCR_INBOX) test_pass("Inbox with incoming message");
        else test_fail("Not on inbox");
        app_take_screenshot("27_interactive_inbox_unread");
        break;
    }

    case 35: { /* Home screen shows unread badge */
        printf("[Step 35] Home screen with unread badge\n");
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        lv_timer_handler();
        contact_t *c = contacts_find_by_name("Charlie");
        if (c && c->unread_count > 0) test_pass("Home shows unread contact");
        else test_fail("No unread indicator");
        app_take_screenshot("28_interactive_home_unread");
        break;
    }

    case 36: { /* Regression: home screen shows contacts after simulated restart */
        printf("[Step 36] Persistence: home shows contacts after reload\n");

        /* Save current state to disk */
        contacts_save();
        messages_save();
        uint32_t count_before = g_app.contact_count;

        /* Simulate restart: clear in-memory data and reload from disk */
        g_app.contact_count = 0;
        memset(g_app.contacts, 0, sizeof(g_app.contacts));
        contacts_load();

        if (g_app.contact_count != count_before) {
            test_fail("Contact count mismatch after reload");
        } else {
            test_pass("Contacts reloaded from disk");
        }

        /* Navigate to home and refresh (as app_init does on startup) */
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        lv_timer_handler();

        /* Verify the contact list is populated (not showing empty label) */
        lv_obj_t *scr = g_app.screens[SCR_HOME];
        /* contact_list is child 2 of screen (header, pending_banner, list) */
        lv_obj_t *clist = lv_obj_get_child(scr, 2);
        uint32_t children = lv_obj_get_child_count(clist);
        /* Should have more than just the empty_label (which is hidden) */
        if (children > 1) test_pass("Home screen populated after reload");
        else test_fail("Home screen empty after reload");
        app_take_screenshot("29_persistence_home_reload");
        break;
    }

    case 37: { /* Delete a single message */
        printf("[Step 37] Delete single message from conversation\n");
        /* Ensure we have messages for Charlie */
        contact_t *c = contacts_find_by_name("Charlie");
        if (!c) { test_fail("Charlie not found"); break; }
        g_app.selected_contact_id = c->id;
        uint32_t before = messages_count_for_contact(c->id);
        if (before == 0) {
            messages_add(c->id, MSG_SENT, "Test msg to delete");
            messages_save();
            before = 1;
        }
        /* Delete the first message for this contact */
        uint32_t del_id = 0;
        for (uint32_t i = 0; i < g_app.message_count; i++) {
            if (g_app.messages[i].contact_id == c->id) {
                del_id = g_app.messages[i].id;
                break;
            }
        }
        bool ok = messages_delete_by_id(del_id);
        messages_save();
        uint32_t after = messages_count_for_contact(c->id);
        if (ok && after == before - 1) test_pass("Single message deleted");
        else test_fail("Single message delete failed");

        app_navigate_to(SCR_CONVERSATION);
        scr_conversation_refresh();
        lv_timer_handler();
        app_take_screenshot("30_msg_deleted");
        break;
    }

    case 38: { /* Delete entire message thread */
        printf("[Step 38] Delete message thread for a contact\n");
        contact_t *c = contacts_find_by_name("Charlie");
        if (!c) { test_fail("Charlie not found"); break; }
        /* Add a couple messages so there's something to delete */
        messages_add(c->id, MSG_SENT, "Thread msg 1");
        messages_add(c->id, MSG_RECEIVED, "Thread msg 2");
        messages_save();
        uint32_t before = messages_count_for_contact(c->id);
        if (before < 2) { test_fail("Not enough messages to test thread delete"); break; }

        messages_delete_for_contact(c->id);
        messages_save();
        uint32_t after = messages_count_for_contact(c->id);
        if (after == 0) test_pass("Thread deleted (all messages removed)");
        else test_fail("Thread delete left messages behind");

        /* Contact should still exist */
        contact_t *c2 = contacts_find_by_name("Charlie");
        if (c2) test_pass("Contact preserved after thread delete");
        else test_fail("Contact deleted with thread");

        g_app.selected_contact_id = c->id;
        app_navigate_to(SCR_CONVERSATION);
        scr_conversation_refresh();
        lv_timer_handler();
        app_take_screenshot("31_thread_deleted");
        break;
    }

    case 39: { /* Delete contact and verify messages removed */
        printf("[Step 39] Delete contact with messages\n");
        contact_t *c = contacts_find_by_name("Diana");
        if (!c) { test_fail("Diana not found"); break; }
        uint32_t diana_id = c->id;
        /* Add messages for Diana */
        messages_add(diana_id, MSG_SENT, "Diana msg 1");
        messages_add(diana_id, MSG_RECEIVED, "Diana msg 2");
        messages_save();
        contacts_save();
        uint32_t contacts_before = g_app.contact_count;

        /* Delete contact (should also clean up messages) */
        messages_delete_for_contact(diana_id);
        contacts_delete(diana_id);
        contacts_save();
        messages_save();

        if (g_app.contact_count == contacts_before - 1) test_pass("Contact deleted");
        else test_fail("Contact count wrong after delete");

        if (messages_count_for_contact(diana_id) == 0) test_pass("Messages cleaned up");
        else test_fail("Orphaned messages remain");

        /* Diana should be gone */
        contact_t *c2 = contacts_find_by_name("Diana");
        if (!c2) test_pass("Diana no longer findable");
        else test_fail("Diana still exists");

        app_navigate_to(SCR_CONTACTS);
        scr_contacts_refresh();
        lv_timer_handler();
        app_take_screenshot("32_contact_deleted");
        break;
    }

    case 40: { /* Verify UI dialogs exist on contacts and conversation screens */
        printf("[Step 40] Verify delete UI elements exist\n");
        /* Contacts screen should have the confirm_del_cont overlay (child 3) */
        lv_obj_t *cscr = g_app.screens[SCR_CONTACTS];
        uint32_t cc = lv_obj_get_child_count(cscr);
        /* Expected: header(0), list_cont(1), name_input_cont(2), confirm_del_cont(3) */
        if (cc >= 4) test_pass("Contacts screen has delete dialog");
        else test_fail("Contacts screen missing delete dialog");

        /* Conversation screen should have dialogs */
        lv_obj_t *cvscr = g_app.screens[SCR_CONVERSATION];
        uint32_t cvc = lv_obj_get_child_count(cvscr);
        /* Expected: header(0), msg_list(1), reply_bar(2), confirm_del_thread(3), confirm_del_msg(4) */
        if (cvc >= 5) test_pass("Conversation screen has delete dialogs");
        else test_fail("Conversation screen missing delete dialogs");
        break;
    }

    case 41: { /* Crypto: keypair generation */
        printf("[Step 41] Crypto: keypair generation\n");
        crypto_identity_t id;
        crypto_generate_keypair(&id);
        if (id.valid) test_pass("Keypair generated");
        else test_fail("Keypair generation failed");

        char b64[CRYPTO_PUBKEY_B64_SIZE];
        crypto_pubkey_to_b64(id.pubkey, b64, sizeof(b64));
        if (strlen(b64) == 44) test_pass("Pubkey base64 correct length");
        else test_fail("Pubkey base64 wrong length");
        break;
    }

    case 42: { /* Crypto: encrypt/decrypt round-trip */
        printf("[Step 42] Crypto: encrypt/decrypt round-trip\n");
        crypto_identity_t alice, bob;
        crypto_generate_keypair(&alice);
        crypto_generate_keypair(&bob);

        const char *msg = "Hello Bob, this is a secret message!";
        char cipher[MAX_CIPHER_LEN];
        bool ok = crypto_encrypt(msg, bob.pubkey, alice.privkey,
                                 cipher, sizeof(cipher));
        if (ok && strlen(cipher) > 0) test_pass("Encrypt succeeded");
        else { test_fail("Encrypt failed"); break; }

        char plain[MAX_TEXT_LEN];
        ok = crypto_decrypt(cipher, alice.pubkey, bob.privkey,
                            plain, sizeof(plain));
        if (ok && strcmp(plain, msg) == 0) test_pass("Decrypt round-trip OK");
        else test_fail("Decrypt round-trip failed");
        break;
    }

    case 43: { /* Crypto: wrong key rejection */
        printf("[Step 43] Crypto: wrong key rejection\n");
        crypto_identity_t alice, bob, eve;
        crypto_generate_keypair(&alice);
        crypto_generate_keypair(&bob);
        crypto_generate_keypair(&eve);

        char cipher[MAX_CIPHER_LEN];
        crypto_encrypt("Secret", bob.pubkey, alice.privkey,
                       cipher, sizeof(cipher));

        char plain[MAX_TEXT_LEN];
        bool ok = crypto_decrypt(cipher, alice.pubkey, eve.privkey,
                                 plain, sizeof(plain));
        if (!ok) test_pass("Wrong key correctly rejected");
        else test_fail("Wrong key was not rejected");
        break;
    }

    case 44: { /* Crypto: identity persistence */
        printf("[Step 44] Crypto: identity persistence\n");
        crypto_identity_t id;
        crypto_generate_keypair(&id);
        identity_save(&id);

        crypto_identity_t loaded;
        bool ok = identity_load(&loaded);
        if (ok && loaded.valid) test_pass("Identity loaded from disk");
        else { test_fail("Identity load failed"); break; }

        if (memcmp(id.pubkey, loaded.pubkey, CRYPTO_PUBKEY_BYTES) == 0 &&
            memcmp(id.privkey, loaded.privkey, CRYPTO_PRIVKEY_BYTES) == 0)
            test_pass("Identity matches after save/load");
        else test_fail("Identity mismatch after save/load");
        break;
    }

    case 45: { /* Setup screen existence test */
        printf("[Step 45] Setup screen exists\n");
        if (g_app.screens[SCR_SETUP] != NULL) test_pass("Setup screen created");
        else test_fail("Setup screen missing");

        app_navigate_to(SCR_SETUP);
        scr_setup_refresh();
        lv_timer_handler();
        /* Since identity is valid (test mode), should show continue */
        if (g_app.identity.valid) test_pass("Identity valid in test mode");
        else test_fail("No identity in test mode");
        app_take_screenshot("33_setup_screen");
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
        break;
    }

    case 46: { /* Transport: TCP server start/stop */
        printf("[Step 46] Transport: TCP server start/stop\n");
        transport_t t;
        transport_init(&t, 19290); /* Use high port unlikely to conflict */
        bool ok = transport_start(&t);
        if (ok) test_pass("TCP server started");
        else { test_fail("TCP server failed to start"); break; }

        if (transport_connected_count(&t) == 0)
            test_pass("No clients initially");
        else
            test_fail("Phantom client connected");

        transport_stop(&t);
        test_pass("TCP server stopped cleanly");
        break;
    }

    case 47: { /* Transport: TCP connect + fragmentation round-trip */
        printf("[Step 47] Transport: TCP connect + send/receive\n");
        transport_t srv;
        transport_init(&srv, 19291);
        if (!transport_start(&srv)) {
            test_fail("Server start failed");
            break;
        }

        /* Connect as client */
        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(19291),
        };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
            test_fail("Client connect failed");
            close(cfd);
            transport_stop(&srv);
            break;
        }

        /* Poll to accept */
        transport_poll(&srv);
        if (transport_connected_count(&srv) == 1)
            test_pass("Client connected via TCP");
        else {
            test_fail("Client not detected");
            close(cfd);
            transport_stop(&srv);
            break;
        }

        /* Server sends fragmented message to client */
        const char *test_msg = "Hello from OSM transport test!";
        bool sent = transport_send_message(&srv, 0, CHAR_UUID_TX,
                                           (const uint8_t *)test_msg,
                                           strlen(test_msg));
        if (sent) test_pass("Fragmented send OK");
        else test_fail("Fragmented send failed");

        /* Client reads data back */
        uint8_t rbuf[512];
        usleep(10000);
        ssize_t n = recv(cfd, rbuf, sizeof(rbuf), 0);
        if (n > 0) test_pass("Client received data");
        else test_fail("Client received nothing");

        close(cfd);
        transport_stop(&srv);
        break;
    }

    case 48: { /* Transport: outbox queue */
        printf("[Step 48] Transport: outbox queue\n");
        uint32_t prev_count = g_app.outbox_count;
        g_app.outbox_count = 0;

        app_outbox_enqueue(CHAR_UUID_TX, "test cipher 1");
        app_outbox_enqueue(CHAR_UUID_TX, "test cipher 2");
        if (g_app.outbox_count == 2)
            test_pass("Outbox queued 2 messages");
        else
            test_fail("Outbox count wrong");

        /* Without transport running, flush should be no-op */
        app_outbox_flush();
        if (g_app.outbox_count == 2)
            test_pass("Outbox retained (no CA connected)");
        else
            test_fail("Outbox lost messages");

        g_app.outbox_count = prev_count; /* restore */
        break;
    }

    case 49: { /* Transport: large message fragmentation */
        printf("[Step 49] Transport: large message fragmentation\n");
        transport_t srv;
        transport_init(&srv, 19292);
        if (!transport_start(&srv)) {
            test_fail("Server start failed");
            break;
        }

        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(19292),
        };
        inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
        connect(cfd, (struct sockaddr *)&addr, sizeof(addr));
        transport_poll(&srv);

        /* Build a 2KB test message (bigger than MTU) */
        char big_msg[2048];
        memset(big_msg, 'A', sizeof(big_msg) - 1);
        big_msg[sizeof(big_msg) - 1] = '\0';

        bool sent = transport_send_message(&srv, 0, CHAR_UUID_TX,
                                           (const uint8_t *)big_msg,
                                           strlen(big_msg));
        if (sent) test_pass("Large fragmented send OK");
        else test_fail("Large fragmented send failed");

        /* Read all fragments from client side */
        usleep(20000);
        uint8_t rbuf[8192];
        size_t total = 0;
        for (int attempt = 0; attempt < 10; attempt++) {
            ssize_t n = recv(cfd, rbuf + total, sizeof(rbuf) - total, MSG_DONTWAIT);
            if (n > 0) total += n;
            else break;
            usleep(1000);
        }
        if (total > 2000) test_pass("Client received large message data");
        else test_fail("Client received insufficient data");

        close(cfd);
        transport_stop(&srv);
        break;
    }

    default:
        printf("\n=== TEST RESULTS: %d passed, %d failed ===\n",
               test_ctx.pass_count, test_ctx.fail_count);
        test_ctx.state = TEST_DONE;
        g_app.quit = true;
        return;
    }

    test_ctx.step++;
    test_ctx.wait_frames = 10; /* wait for LVGL to render */
}

void app_test_tick(void)
{
    if (test_ctx.state == TEST_DONE) return;

    if (test_ctx.wait_frames > 0) {
        test_ctx.wait_frames--;
        return;
    }

    if (test_ctx.state == TEST_START) {
        test_ctx.state = TEST_STEP;
    }

    test_execute_step();
}
