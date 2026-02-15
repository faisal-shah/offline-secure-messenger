/**
 * Assign Key Screen — Let user assign an incoming pubkey to a contact
 *
 * Shows the received pubkey and lets the user either:
 *   - Assign it to an existing PENDING_SENT contact (→ ESTABLISHED)
 *   - Create a new contact with the key (→ PENDING_RECEIVED)
 *   - Dismiss and handle later
 */
#include "scr_assign_key.h"
#include "scr_home.h"
#include "scr_contacts.h"
#include "scr_key_exchange.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../crypto.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *body;
static lv_obj_t *info_lbl;
static lv_obj_t *key_display;
static lv_obj_t *contact_list;
static lv_obj_t *new_contact_cont;
static lv_obj_t *name_ta;
static lv_obj_t *badge_lbl;

/* Index into g_app.pending_keys currently being assigned */
static uint32_t current_pending_idx;

static void back_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_HOME);
    scr_home_refresh();
}

static void assign_to_contact_cb(lv_event_t *e)
{
    uint32_t contact_idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (contact_idx >= g_app.contact_count) return;
    if (current_pending_idx >= g_app.pending_key_count) return;

    contact_t *c = &g_app.contacts[contact_idx];
    const char *pubkey = g_app.pending_keys[current_pending_idx].pubkey_b64;

    /* Store their pubkey and establish */
    strncpy(c->public_key, pubkey, MAX_KEY_LEN - 1);
    c->status = CONTACT_ESTABLISHED;
    contacts_save();

    char ctx[128];
    snprintf(ctx, sizeof(ctx), "KEX assigned to %s → ESTABLISHED", c->name);
    app_log(ctx, pubkey);

    /* Remove from pending queue */
    app_pending_key_remove(current_pending_idx);
    app_pending_keys_save();

    /* If more pending keys, refresh; otherwise go home */
    if (g_app.pending_key_count > 0) {
        current_pending_idx = 0;
        scr_assign_key_refresh();
    } else {
        app_navigate_to(SCR_HOME);
        scr_home_refresh();
    }
}

static void show_new_contact_cb(lv_event_t *e)
{
    (void)e;
    lv_textarea_set_text(name_ta, "");
    lv_obj_clear_flag(new_contact_cont, LV_OBJ_FLAG_HIDDEN);
}

static void cancel_new_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(new_contact_cont, LV_OBJ_FLAG_HIDDEN);
}

static void confirm_new_cb(lv_event_t *e)
{
    (void)e;
    const char *name = lv_textarea_get_text(name_ta);
    if (!name || strlen(name) == 0) return;
    if (current_pending_idx >= g_app.pending_key_count) return;

    const char *pubkey = g_app.pending_keys[current_pending_idx].pubkey_b64;

    /* Create new contact with their pubkey */
    contact_t *c = contacts_add(name);
    if (!c) return;
    strncpy(c->public_key, pubkey, MAX_KEY_LEN - 1);
    c->status = CONTACT_PENDING_RECEIVED;
    contacts_save();

    char ctx[128];
    snprintf(ctx, sizeof(ctx), "KEX → new contact '%s' (PENDING_RECEIVED)", name);
    app_log(ctx, pubkey);

    /* Remove from pending queue */
    app_pending_key_remove(current_pending_idx);
    app_pending_keys_save();

    lv_obj_add_flag(new_contact_cont, LV_OBJ_FLAG_HIDDEN);

    /* Navigate to key exchange screen for user to send their key back */
    g_app.selected_contact_id = c->id;
    app_navigate_to(SCR_KEY_EXCHANGE);
    scr_key_exchange_refresh();
}

static void later_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_HOME);
    scr_home_refresh();
}

void scr_assign_key_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_ASSIGN_KEY] = scr;
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1A2E), 0);

    /* Header */
    lv_obj_t *header = lv_obj_create(scr);
    lv_obj_set_size(header, DEVICE_HOR_RES, 28);
    lv_obj_set_pos(header, 0, 0);
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
    lv_label_set_text(title, "Assign Key");
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);

    badge_lbl = lv_label_create(header);
    lv_label_set_text(badge_lbl, "");
    lv_obj_set_style_text_color(badge_lbl, lv_color_hex(0xFF9100), 0);
    lv_obj_set_style_text_font(badge_lbl, &lv_font_montserrat_10, 0);
    lv_obj_align(badge_lbl, LV_ALIGN_RIGHT_MID, 0, 0);

    /* Body */
    body = lv_obj_create(scr);
    lv_obj_set_size(body, DEVICE_HOR_RES, DEVICE_VER_RES - 28);
    lv_obj_set_pos(body, 0, 28);
    lv_obj_set_style_bg_color(body, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(body, 0, 0);
    lv_obj_set_style_radius(body, 0, 0);
    lv_obj_set_style_pad_all(body, 6, 0);
    lv_obj_set_layout(body, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(body, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(body, 4, 0);

    /* Info label */
    info_lbl = lv_label_create(body);
    lv_obj_set_style_text_color(info_lbl, lv_color_hex(0xBBBBBB), 0);
    lv_obj_set_style_text_font(info_lbl, &lv_font_montserrat_10, 0);
    lv_obj_set_width(info_lbl, DEVICE_HOR_RES - 20);
    lv_label_set_long_mode(info_lbl, LV_LABEL_LONG_WRAP);

    /* Key display */
    key_display = lv_label_create(body);
    lv_obj_set_style_text_color(key_display, lv_color_hex(0x00E676), 0);
    lv_obj_set_style_text_font(key_display, &lv_font_montserrat_10, 0);
    lv_obj_set_width(key_display, DEVICE_HOR_RES - 20);
    lv_label_set_long_mode(key_display, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_bg_color(key_display, lv_color_hex(0x0D1117), 0);
    lv_obj_set_style_bg_opa(key_display, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(key_display, 4, 0);
    lv_obj_set_style_radius(key_display, 4, 0);

    /* Scrollable contact list */
    contact_list = lv_obj_create(body);
    lv_obj_set_width(contact_list, DEVICE_HOR_RES - 20);
    lv_obj_set_flex_grow(contact_list, 1);
    lv_obj_set_style_bg_opa(contact_list, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(contact_list, 0, 0);
    lv_obj_set_style_pad_all(contact_list, 0, 0);
    lv_obj_set_layout(contact_list, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(contact_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(contact_list, 3, 0);

    /* New contact overlay (hidden by default) */
    new_contact_cont = lv_obj_create(scr);
    lv_obj_set_size(new_contact_cont, 280, 100);
    lv_obj_center(new_contact_cont);
    lv_obj_set_style_bg_color(new_contact_cont, lv_color_hex(0x0F3460), 0);
    lv_obj_set_style_border_color(new_contact_cont, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_border_width(new_contact_cont, 2, 0);
    lv_obj_set_style_radius(new_contact_cont, 8, 0);
    lv_obj_set_style_pad_all(new_contact_cont, 8, 0);
    lv_obj_add_flag(new_contact_cont, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *prompt = lv_label_create(new_contact_cont);
    lv_label_set_text(prompt, "Contact Name:");
    lv_obj_set_style_text_color(prompt, lv_color_white(), 0);
    lv_obj_align(prompt, LV_ALIGN_TOP_LEFT, 0, 0);

    name_ta = lv_textarea_create(new_contact_cont);
    lv_obj_set_size(name_ta, 260, 30);
    lv_obj_align(name_ta, LV_ALIGN_TOP_LEFT, 0, 20);
    lv_textarea_set_one_line(name_ta, true);
    lv_textarea_set_placeholder_text(name_ta, "Enter name...");
    if (g_app.dev_group) lv_group_add_obj(g_app.dev_group, name_ta);

    lv_obj_t *ok_btn = lv_button_create(new_contact_cont);
    lv_obj_set_size(ok_btn, 80, 26);
    lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(ok_btn, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(ok_btn, confirm_new_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *ok_lbl = lv_label_create(ok_btn);
    lv_label_set_text(ok_lbl, "Create");
    lv_obj_set_style_text_color(ok_lbl, lv_color_white(), 0);
    lv_obj_center(ok_lbl);

    lv_obj_t *cancel_btn = lv_button_create(new_contact_cont);
    lv_obj_set_size(cancel_btn, 80, 26);
    lv_obj_align(cancel_btn, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_hex(0x424242), 0);
    lv_obj_add_event_cb(cancel_btn, cancel_new_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, lv_color_white(), 0);
    lv_obj_center(cancel_lbl);
}

void scr_assign_key_refresh(void)
{
    lv_obj_clean(contact_list);

    if (g_app.pending_key_count == 0) {
        lv_label_set_text(info_lbl, "No pending keys.");
        lv_label_set_text(key_display, "");
        lv_label_set_text(badge_lbl, "");
        return;
    }

    current_pending_idx = 0;
    const pending_key_t *pk = &g_app.pending_keys[current_pending_idx];

    if (g_app.pending_key_count > 1) {
        lv_label_set_text_fmt(badge_lbl, "%u keys", g_app.pending_key_count);
    } else {
        lv_label_set_text(badge_lbl, "1 key");
    }

    lv_label_set_text(info_lbl,
        "Received a public key. Assign it to\n"
        "a pending contact or create a new one:");
    lv_label_set_text_fmt(key_display, "Key: %.40s...", pk->pubkey_b64);

    /* List PENDING_SENT contacts as assignment targets */
    bool has_pending = false;
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        contact_t *c = &g_app.contacts[i];
        if (c->status != CONTACT_PENDING_SENT) continue;
        has_pending = true;

        lv_obj_t *btn = lv_button_create(contact_list);
        lv_obj_set_size(btn, LV_PCT(100), 30);
        lv_obj_set_style_bg_color(btn, lv_color_hex(0x16213E), 0);
        lv_obj_set_style_radius(btn, 4, 0);
        lv_obj_add_event_cb(btn, assign_to_contact_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)i);

        lv_obj_t *ico = lv_label_create(btn);
        lv_label_set_text(ico, LV_SYMBOL_UPLOAD);
        lv_obj_set_style_text_color(ico, lv_color_hex(0xFFD600), 0);
        lv_obj_align(ico, LV_ALIGN_LEFT_MID, 4, 0);

        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text_fmt(lbl, "%s (awaiting reply)", c->name);
        lv_obj_set_style_text_color(lbl, lv_color_white(), 0);
        lv_obj_align(lbl, LV_ALIGN_LEFT_MID, 24, 0);
    }

    if (!has_pending) {
        lv_obj_t *lbl = lv_label_create(contact_list);
        lv_label_set_text(lbl, "No pending contacts.");
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, 0);
    }

    /* "Create New Contact" button */
    lv_obj_t *new_btn = lv_button_create(contact_list);
    lv_obj_set_size(new_btn, LV_PCT(100), 30);
    lv_obj_set_style_bg_color(new_btn, lv_color_hex(0x00C853), 0);
    lv_obj_set_style_radius(new_btn, 4, 0);
    lv_obj_add_event_cb(new_btn, show_new_contact_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *new_lbl = lv_label_create(new_btn);
    lv_label_set_text(new_lbl, LV_SYMBOL_PLUS " Create New Contact");
    lv_obj_set_style_text_color(new_lbl, lv_color_white(), 0);
    lv_obj_center(new_lbl);

    /* "Later" button */
    lv_obj_t *later_btn = lv_button_create(contact_list);
    lv_obj_set_size(later_btn, LV_PCT(100), 26);
    lv_obj_set_style_bg_color(later_btn, lv_color_hex(0x424242), 0);
    lv_obj_set_style_radius(later_btn, 4, 0);
    lv_obj_add_event_cb(later_btn, later_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *later_lbl = lv_label_create(later_btn);
    lv_label_set_text(later_lbl, "Later");
    lv_obj_set_style_text_color(later_lbl, lv_color_hex(0xBBBBBB), 0);
    lv_obj_center(later_lbl);
}
