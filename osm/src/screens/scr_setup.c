/**
 * Setup screen — first-launch keypair generation wizard.
 * Gates access to all other screens until a keypair exists.
 */
#include "scr_setup.h"
#include "../app.h"
#include "../data/identity.h"
#include "scr_home.h"
#include <stdio.h>

static lv_obj_t *info_lbl;
static lv_obj_t *pubkey_lbl;
static lv_obj_t *generate_btn;
static lv_obj_t *continue_btn;

static void generate_cb(lv_event_t *e)
{
    (void)e;
    crypto_generate_keypair(&g_app.identity);
    identity_save(&g_app.identity);

    char b64[CRYPTO_PUBKEY_B64_SIZE];
    crypto_pubkey_to_b64(g_app.identity.pubkey, b64, sizeof(b64));

    char text[128];
    snprintf(text, sizeof(text), "Your public key:\n%.20s...", b64);
    lv_label_set_text(pubkey_lbl, text);
    lv_obj_clear_flag(pubkey_lbl, LV_OBJ_FLAG_HIDDEN);

    lv_obj_add_flag(generate_btn, LV_OBJ_FLAG_HIDDEN);
    lv_obj_clear_flag(continue_btn, LV_OBJ_FLAG_HIDDEN);

    lv_label_set_text(info_lbl, LV_SYMBOL_OK " Keypair generated!");
    lv_obj_set_style_text_color(info_lbl, lv_color_hex(0x00E676), 0);
}

static void continue_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_HOME);
    scr_home_refresh();
}

void scr_setup_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_SETUP] = scr;
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1A2E), 0);

    /* Header */
    lv_obj_t *header = lv_obj_create(scr);
    lv_obj_set_size(header, DEVICE_HOR_RES, 36);
    lv_obj_set_pos(header, 0, 0);
    lv_obj_set_style_bg_color(header, lv_color_hex(0x16213E), 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_radius(header, 0, 0);
    lv_obj_set_style_pad_hor(header, 8, 0);
    lv_obj_set_scrollbar_mode(header, LV_SCROLLBAR_MODE_OFF);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, LV_SYMBOL_SETTINGS " Device Setup");
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    /* Info text */
    info_lbl = lv_label_create(scr);
    lv_label_set_text(info_lbl,
        "Welcome to Offline Secure Messenger.\n\n"
        "Generate your encryption keypair to\n"
        "get started. This key will be used\n"
        "for all secure communications.");
    lv_obj_set_width(info_lbl, DEVICE_HOR_RES - 32);
    lv_label_set_long_mode(info_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(info_lbl, lv_color_hex(0xCCCCCC), 0);
    lv_obj_set_style_text_font(info_lbl, &lv_font_montserrat_12, 0);
    lv_obj_set_pos(info_lbl, 16, 48);

    /* Generate button */
    generate_btn = lv_button_create(scr);
    lv_obj_set_size(generate_btn, 200, 40);
    lv_obj_align(generate_btn, LV_ALIGN_CENTER, 0, 10);
    lv_obj_set_style_bg_color(generate_btn, lv_color_hex(0x0F3460), 0);
    lv_obj_add_event_cb(generate_btn, generate_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *gen_lbl = lv_label_create(generate_btn);
    lv_label_set_text(gen_lbl, LV_SYMBOL_CHARGE " Generate Keypair");
    lv_obj_set_style_text_color(gen_lbl, lv_color_white(), 0);
    lv_obj_center(gen_lbl);

    /* Public key display (hidden initially) */
    pubkey_lbl = lv_label_create(scr);
    lv_label_set_text(pubkey_lbl, "");
    lv_obj_set_width(pubkey_lbl, DEVICE_HOR_RES - 32);
    lv_label_set_long_mode(pubkey_lbl, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(pubkey_lbl, lv_color_hex(0x00E676), 0);
    lv_obj_set_style_text_font(pubkey_lbl, &lv_font_montserrat_10, 0);
    lv_obj_align(pubkey_lbl, LV_ALIGN_CENTER, 0, 50);
    lv_obj_add_flag(pubkey_lbl, LV_OBJ_FLAG_HIDDEN);

    /* Continue button (hidden until keypair generated) */
    continue_btn = lv_button_create(scr);
    lv_obj_set_size(continue_btn, 200, 40);
    lv_obj_align(continue_btn, LV_ALIGN_BOTTOM_MID, 0, -16);
    lv_obj_set_style_bg_color(continue_btn, lv_color_hex(0x238636), 0);
    lv_obj_add_event_cb(continue_btn, continue_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *cont_lbl = lv_label_create(continue_btn);
    lv_label_set_text(cont_lbl, LV_SYMBOL_RIGHT " Continue");
    lv_obj_set_style_text_color(cont_lbl, lv_color_white(), 0);
    lv_obj_center(cont_lbl);
    lv_obj_add_flag(continue_btn, LV_OBJ_FLAG_HIDDEN);
}

void scr_setup_refresh(void)
{
    if (g_app.identity.valid) {
        lv_label_set_text(info_lbl, LV_SYMBOL_OK " Keypair generated!");
        lv_obj_set_style_text_color(info_lbl, lv_color_hex(0x00E676), 0);

        char b64[CRYPTO_PUBKEY_B64_SIZE];
        crypto_pubkey_to_b64(g_app.identity.pubkey, b64, sizeof(b64));
        char text[128];
        snprintf(text, sizeof(text), "Your public key:\n%.20s...", b64);
        lv_label_set_text(pubkey_lbl, text);
        lv_obj_clear_flag(pubkey_lbl, LV_OBJ_FLAG_HIDDEN);

        lv_obj_add_flag(generate_btn, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(continue_btn, LV_OBJ_FLAG_HIDDEN);
    }
}
