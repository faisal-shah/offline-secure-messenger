/**
 * ui_common.c — Shared status bar and tab bar for all screens
 */
#include "ui_common.h"
#include "scr_contacts.h"
#include "scr_inbox.h"
#include "scr_assign_key.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../transport/transport.h"
#include <stdio.h>

/* ---- Status Bar (20px) ---- */

/* Child indices inside the status bar */
#define SB_CHILD_TITLE   0
#define SB_CHILD_STATUS  1
#define SB_CHILD_PENDING 2

static void pending_keys_tap_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_ASSIGN_KEY);
    scr_assign_key_refresh();
}

lv_obj_t *ui_status_bar_create(lv_obj_t *parent)
{
    lv_obj_t *bar = lv_obj_create(parent);
    lv_obj_set_size(bar, DEVICE_HOR_RES, 20);
    lv_obj_set_pos(bar, 0, 0);
    lv_obj_set_style_bg_color(bar, lv_color_hex(0x16213E), 0);
    lv_obj_set_style_border_width(bar, 0, 0);
    lv_obj_set_style_radius(bar, 0, 0);
    lv_obj_set_style_pad_all(bar, 2, 0);
    lv_obj_set_scrollbar_mode(bar, LV_SCROLLBAR_MODE_OFF);

    /* [0] Device name / title */
    lv_obj_t *title = lv_label_create(bar);
    if (g_app.device_name[0]) {
        lv_label_set_text_fmt(title, LV_SYMBOL_EYE_CLOSE " %s", g_app.device_name);
    } else {
        lv_label_set_text(title, LV_SYMBOL_EYE_CLOSE " OSM");
    }
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_10, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    /* [1] CA status indicator */
    lv_obj_t *ca_lbl = lv_label_create(bar);
    lv_label_set_text(ca_lbl, LV_SYMBOL_CLOSE " CA");
    lv_obj_set_style_text_color(ca_lbl, lv_color_hex(0xFF1744), 0);
    lv_obj_set_style_text_font(ca_lbl, &lv_font_montserrat_10, 0);
    lv_obj_align(ca_lbl, LV_ALIGN_RIGHT_MID, 0, 0);

    /* [2] Pending keys badge (hidden by default) */
    lv_obj_t *pending = lv_button_create(bar);
    lv_obj_set_size(pending, 22, 16);
    lv_obj_align(pending, LV_ALIGN_RIGHT_MID, -50, 0);
    lv_obj_set_style_bg_color(pending, lv_color_hex(0xFF6D00), 0);
    lv_obj_set_style_radius(pending, 8, 0);
    lv_obj_set_style_pad_all(pending, 0, 0);
    lv_obj_add_event_cb(pending, pending_keys_tap_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_add_flag(pending, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *pk_lbl = lv_label_create(pending);
    lv_label_set_text(pk_lbl, "0");
    lv_obj_set_style_text_color(pk_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(pk_lbl, &lv_font_montserrat_10, 0);
    lv_obj_center(pk_lbl);

    return bar;
}

void ui_status_bar_refresh(lv_obj_t *bar)
{
    if (!bar) return;

    /* CA status — child [1] */
    lv_obj_t *ca_lbl = lv_obj_get_child(bar, SB_CHILD_STATUS);
    int ca_count = transport_connected_count(&g_app.transport);

    if (g_app.storage_full) {
        lv_label_set_text(ca_lbl, LV_SYMBOL_WARNING " FULL");
        lv_obj_set_style_text_color(ca_lbl, lv_color_hex(0xFF0000), 0);
    } else if (g_app.storage_error) {
        lv_label_set_text(ca_lbl, LV_SYMBOL_WARNING " STOR");
        lv_obj_set_style_text_color(ca_lbl, lv_color_hex(0xFF6D00), 0);
    } else if (ca_count > 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), LV_SYMBOL_OK " CA:%d", ca_count);
        lv_label_set_text(ca_lbl, buf);
        lv_obj_set_style_text_color(ca_lbl, lv_color_hex(0x00E676), 0);
    } else {
        lv_label_set_text(ca_lbl, LV_SYMBOL_CLOSE " CA");
        lv_obj_set_style_text_color(ca_lbl, lv_color_hex(0xFF1744), 0);
    }

    /* Pending keys badge — child [2] */
    lv_obj_t *pending = lv_obj_get_child(bar, SB_CHILD_PENDING);
    if (g_app.pending_key_count > 0) {
        lv_obj_clear_flag(pending, LV_OBJ_FLAG_HIDDEN);
        lv_obj_t *pk_lbl = lv_obj_get_child(pending, 0);
        char buf[8];
        snprintf(buf, sizeof(buf), LV_SYMBOL_DOWNLOAD "%u", g_app.pending_key_count);
        lv_label_set_text(pk_lbl, buf);
    } else {
        lv_obj_add_flag(pending, LV_OBJ_FLAG_HIDDEN);
    }
}

/* ---- Tab Bar (32px) ---- */

static void tab_contacts_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_CONTACTS);
    scr_contacts_refresh();
}

static void tab_inbox_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_INBOX);
    scr_inbox_refresh();
}

lv_obj_t *ui_tab_bar_create(lv_obj_t *parent, int active_tab)
{
    lv_obj_t *bar = lv_obj_create(parent);
    lv_obj_set_size(bar, DEVICE_HOR_RES, 32);
    lv_obj_set_pos(bar, 0, DEVICE_VER_RES - 32);
    lv_obj_set_style_bg_color(bar, lv_color_hex(0x16213E), 0);
    lv_obj_set_style_border_width(bar, 0, 0);
    lv_obj_set_style_radius(bar, 0, 0);
    lv_obj_set_style_pad_all(bar, 2, 0);
    lv_obj_set_layout(bar, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bar, LV_FLEX_ALIGN_SPACE_EVENLY,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_scrollbar_mode(bar, LV_SCROLLBAR_MODE_OFF);

    static const char *labels[] = {
        LV_SYMBOL_LIST " Contacts",
        LV_SYMBOL_ENVELOPE " Inbox"
    };
    static lv_event_cb_t cbs[] = { tab_contacts_cb, tab_inbox_cb };

    for (int i = 0; i < 2; i++) {
        lv_obj_t *btn = lv_button_create(bar);
        lv_obj_set_size(btn, 150, 26);
        lv_obj_set_style_radius(btn, 4, 0);
        lv_obj_add_event_cb(btn, cbs[i], LV_EVENT_CLICKED, NULL);

        if (i == active_tab) {
            lv_obj_set_style_bg_color(btn, lv_color_hex(0x00B0FF), 0);
        } else {
            lv_obj_set_style_bg_color(btn, lv_color_hex(0x0F3460), 0);
        }

        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text(lbl, labels[i]);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, 0);
        lv_obj_set_style_text_color(lbl, lv_color_white(), 0);
        lv_obj_center(lbl);
    }

    return bar;
}

void ui_tab_bar_refresh(lv_obj_t *bar)
{
    if (!bar) return;

    /* Update inbox unread badge on the Inbox button (child [1]) */
    lv_obj_t *inbox_btn = lv_obj_get_child(bar, 1);
    if (!inbox_btn) return;

    uint32_t total_unread = 0;
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        total_unread += g_app.contacts[i].unread_count;
    }

    lv_obj_t *lbl = lv_obj_get_child(inbox_btn, 0);
    if (total_unread > 0) {
        char buf[32];
        snprintf(buf, sizeof(buf), LV_SYMBOL_ENVELOPE " Inbox (%u)", total_unread);
        lv_label_set_text(lbl, buf);
    } else {
        lv_label_set_text(lbl, LV_SYMBOL_ENVELOPE " Inbox");
    }
}
