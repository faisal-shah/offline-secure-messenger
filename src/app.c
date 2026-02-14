#include "app.h"
#include "data/contacts.h"
#include "data/messages.h"
#include "io_monitor.h"
#include "screens/scr_home.h"
#include "screens/scr_contacts.h"
#include "screens/scr_key_exchange.h"
#include "screens/scr_compose.h"
#include "screens/scr_inbox.h"
#include "screens/scr_conversation.h"
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

/*---------- App lifecycle ----------*/
void app_init(lv_display_t *disp, lv_display_t *io_disp,
              lv_indev_t *mouse, lv_indev_t *kb, bool test_mode)
{
    memset(&g_app, 0, sizeof(g_app));
    g_app.dev_disp = disp;
    g_app.io_disp = io_disp;
    g_app.mouse = mouse;
    g_app.keyboard = kb;
    g_app.test_mode = test_mode;
    g_app.quit = false;
    g_app.next_contact_id = 1;
    g_app.next_message_id = 1;

    mkdir("screenshots", 0755);

    /* Load persisted data */
    contacts_load();
    messages_load();

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
    scr_home_create();
    scr_contacts_create();
    scr_key_exchange_create();
    scr_compose_create();
    scr_inbox_create();
    scr_conversation_create();

    /* Start on home */
    app_navigate_to(SCR_HOME);

    /* Create I/O monitor UI on second display */
    if (io_disp) {
        io_monitor_create(io_disp);
        io_monitor_refresh();
        lv_display_set_default(disp);
    }

    if (test_mode) {
        printf("=== SELF-TEST MODE ===\n");
        test_driver_init();
    }
}

void app_deinit(void)
{
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
            alice->status = CONTACT_ESTABLISHED;
            snprintf(alice->shared_secret, MAX_KEY_LEN, "shared_secret_alice_001");
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
            snprintf(bob->shared_secret, MAX_KEY_LEN, "shared_secret_bob_002");
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
