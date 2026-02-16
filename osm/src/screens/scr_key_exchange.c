/**
 * Key Exchange Wizard — Guided DH key exchange flow
 */
#include "scr_key_exchange.h"
#include "scr_contacts.h"
#include "ui_common.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../crypto.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *kex_status_bar;
static lv_obj_t *status_icon;
static lv_obj_t *contact_name_lbl;
static lv_obj_t *step_lbl;
static lv_obj_t *info_lbl;
static lv_obj_t *key_display;
static lv_obj_t *action_btn;
static lv_obj_t *action_lbl;

static void back_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_CONTACTS);
    scr_contacts_refresh();
}

static void action_cb(lv_event_t *e)
{
    (void)e;
    contact_t *c = contacts_find_by_id(g_app.selected_contact_id);
    if (!c) return;

    switch (c->status) {
    case CONTACT_PENDING_SENT:
        /* In real device: would wait for incoming data. In prototype: no-op */
        break;
    case CONTACT_PENDING_RECEIVED:
        /* Send our pubkey; peer's key is already in c->public_key */
        {
            char our_b64[CRYPTO_PUBKEY_B64_SIZE];
            crypto_pubkey_to_b64(g_app.identity.pubkey,
                                 our_b64, sizeof(our_b64));
            app_send_key_exchange(our_b64);
            char ctx[128];
            snprintf(ctx, sizeof(ctx), "DH Key -> %s", c->name);
            app_log(ctx, our_b64);
        }
        c->status = CONTACT_ESTABLISHED;
        contacts_save();

        scr_key_exchange_refresh();
        break;
    case CONTACT_ESTABLISHED:
        app_navigate_to(SCR_CONTACTS);
        scr_contacts_refresh();
        break;
    }
}

void scr_key_exchange_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_KEY_EXCHANGE] = scr;
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1A2E), 0);

    /* Status bar */
    kex_status_bar = ui_status_bar_create(scr);

    /* Header (below status bar) */
    lv_obj_t *header = lv_obj_create(scr);
    lv_obj_set_size(header, DEVICE_HOR_RES, 28);
    lv_obj_set_pos(header, 0, 20);
    lv_obj_set_style_bg_color(header, lv_color_hex(0x16213E), 0);
    lv_obj_set_style_border_width(header, 0, 0);
    lv_obj_set_style_radius(header, 0, 0);
    lv_obj_set_style_pad_all(header, 4, 0);
    lv_obj_set_scrollbar_mode(header, LV_SCROLLBAR_MODE_OFF);

    lv_obj_t *back_btn = lv_button_create(header);
    lv_obj_set_size(back_btn, 40, 22);
    lv_obj_align(back_btn, LV_ALIGN_LEFT_MID, 0, 0);
    lv_obj_set_style_bg_color(back_btn, lv_color_hex(0x0F3460), 0);
    lv_obj_add_event_cb(back_btn, back_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *blbl = lv_label_create(back_btn);
    lv_label_set_text(blbl, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(blbl, lv_color_white(), 0);
    lv_obj_center(blbl);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "Key Exchange");
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);

    /* Body */
    lv_obj_t *body = lv_obj_create(scr);
    lv_obj_set_size(body, DEVICE_HOR_RES, DEVICE_VER_RES - 48);
    lv_obj_set_pos(body, 0, 48);
    lv_obj_set_style_bg_color(body, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(body, 0, 0);
    lv_obj_set_style_radius(body, 0, 0);
    lv_obj_set_style_pad_all(body, 8, 0);
    lv_obj_set_layout(body, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(body, 6, 0);
    lv_obj_set_flex_align(body, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    /* Status icon (large) */
    status_icon = lv_label_create(body);
    lv_obj_set_style_text_font(status_icon, &lv_font_montserrat_16, 0);

    /* Contact name */
    contact_name_lbl = lv_label_create(body);
    lv_obj_set_style_text_color(contact_name_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(contact_name_lbl, &lv_font_montserrat_14, 0);

    /* Step description */
    step_lbl = lv_label_create(body);
    lv_obj_set_style_text_color(step_lbl, lv_color_hex(0x00B0FF), 0);

    /* Info text */
    info_lbl = lv_label_create(body);
    lv_obj_set_style_text_color(info_lbl, lv_color_hex(0xBBBBBB), 0);
    lv_obj_set_style_text_font(info_lbl, &lv_font_montserrat_10, 0);
    lv_obj_set_width(info_lbl, DEVICE_HOR_RES - 24);
    lv_label_set_long_mode(info_lbl, LV_LABEL_LONG_WRAP);

    /* Key display (monospace-ish) */
    key_display = lv_label_create(body);
    lv_obj_set_style_text_color(key_display, lv_color_hex(0x00E676), 0);
    lv_obj_set_style_text_font(key_display, &lv_font_montserrat_10, 0);
    lv_obj_set_width(key_display, DEVICE_HOR_RES - 24);
    lv_label_set_long_mode(key_display, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_bg_color(key_display, lv_color_hex(0x0D1117), 0);
    lv_obj_set_style_bg_opa(key_display, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(key_display, 4, 0);
    lv_obj_set_style_radius(key_display, 4, 0);

    /* Action button */
    action_btn = lv_button_create(body);
    lv_obj_set_size(action_btn, 200, 32);
    lv_obj_set_style_bg_color(action_btn, lv_color_hex(0x0F3460), 0);
    lv_obj_add_event_cb(action_btn, action_cb, LV_EVENT_CLICKED, NULL);
    action_lbl = lv_label_create(action_btn);
    lv_obj_set_style_text_color(action_lbl, lv_color_white(), 0);
    lv_obj_center(action_lbl);
}

void scr_key_exchange_refresh(void)
{
    ui_status_bar_refresh(kex_status_bar);

    contact_t *c = contacts_find_by_id(g_app.selected_contact_id);
    if (!c) return;

    lv_label_set_text_fmt(contact_name_lbl, "Contact: %s", c->name);

    switch (c->status) {
    case CONTACT_PENDING_SENT:
        lv_label_set_text(status_icon, LV_SYMBOL_UPLOAD);
        lv_obj_set_style_text_color(status_icon, lv_color_hex(0xFFD600), 0);
        lv_label_set_text(step_lbl, "Step 1/2: Key Sent");
        lv_label_set_text(info_lbl,
            "Your public key has been sent to the\n"
            "connected device. Share it with this\n"
            "contact and wait for their reply.");
        lv_label_set_text_fmt(key_display, "Your key:\n%.32s...", c->public_key);
        lv_label_set_text(action_lbl, LV_SYMBOL_REFRESH " Waiting...");
        lv_obj_set_style_bg_color(action_btn, lv_color_hex(0x424242), 0);
        break;

    case CONTACT_PENDING_RECEIVED:
        lv_label_set_text(status_icon, LV_SYMBOL_DOWNLOAD);
        lv_obj_set_style_text_color(status_icon, lv_color_hex(0xFF9100), 0);
        lv_label_set_text(step_lbl, "Step 2/2: Send Your Key");
        lv_label_set_text(info_lbl,
            "Received their public key. Tap the\n"
            "button below to send your key back\n"
            "and establish the secure channel.");
        lv_label_set_text_fmt(key_display, "Their key:\n%.32s...", c->public_key);
        lv_label_set_text(action_lbl, LV_SYMBOL_OK " Complete Exchange");
        lv_obj_set_style_bg_color(action_btn, lv_color_hex(0x00C853), 0);
        break;

    case CONTACT_ESTABLISHED:
        lv_label_set_text(status_icon, LV_SYMBOL_OK);
        lv_obj_set_style_text_color(status_icon, lv_color_hex(0x00E676), 0);
        lv_label_set_text(step_lbl, "Secure Channel Established!");
        lv_label_set_text(info_lbl,
            "Key exchange complete. You can now\n"
            "send and receive encrypted messages\n"
            "with this contact.");
        lv_label_set_text(key_display, LV_SYMBOL_EYE_CLOSE " Encryption active");
        lv_label_set_text(action_lbl, LV_SYMBOL_LEFT " Back to Contacts");
        lv_obj_set_style_bg_color(action_btn, lv_color_hex(0x0F3460), 0);
        break;
    }
}

lv_obj_t *scr_key_exchange_get_action_btn(void) { return action_btn; }
