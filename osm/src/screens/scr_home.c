/**
 * Home Screen — Primary navigation hub
 * Shows contact list with status + unread, bottom nav bar
 */
#include "scr_home.h"
#include "scr_contacts.h"
#include "scr_compose.h"
#include "scr_inbox.h"
#include "scr_conversation.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../data/messages.h"
#include "../transport/transport.h"
#include <stdio.h>

static lv_obj_t *contact_list;
static lv_obj_t *empty_label;
static lv_obj_t *ca_status_lbl;

static void nav_contacts_cb(lv_event_t *e) { (void)e; app_navigate_to(SCR_CONTACTS); scr_contacts_refresh(); }
static void nav_compose_cb(lv_event_t *e)  { (void)e; app_navigate_to(SCR_COMPOSE); scr_compose_refresh(); }
static void nav_inbox_cb(lv_event_t *e)    { (void)e; app_navigate_to(SCR_INBOX); scr_inbox_refresh(); }

static void contact_clicked_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        contact_t *c = &g_app.contacts[idx];
        g_app.selected_contact_id = c->id;
        if (c->status == CONTACT_ESTABLISHED) {
            c->unread_count = 0;
            contacts_save();
            app_navigate_to(SCR_CONVERSATION);
            scr_conversation_refresh();
        } else {
            app_navigate_to(SCR_CONTACTS);
            scr_contacts_refresh();
        }
    }
}

void scr_home_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_HOME] = scr;
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

    lv_obj_t *title = lv_label_create(header);
    if (g_app.device_name[0]) {
        lv_label_set_text_fmt(title, LV_SYMBOL_EYE_CLOSE " %s", g_app.device_name);
    } else {
        lv_label_set_text(title, LV_SYMBOL_EYE_CLOSE " SecureComm");
    }
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    /* CA connection indicator */
    ca_status_lbl = lv_label_create(header);
    lv_label_set_text(ca_status_lbl, LV_SYMBOL_CLOSE " CA");
    lv_obj_set_style_text_color(ca_status_lbl, lv_color_hex(0xFF1744), 0);
    lv_obj_set_style_text_font(ca_status_lbl, &lv_font_montserrat_10, 0);
    lv_obj_align(ca_status_lbl, LV_ALIGN_RIGHT_MID, 0, 0);

    /* Main area */
    contact_list = lv_obj_create(scr);
    lv_obj_set_size(contact_list, DEVICE_HOR_RES, DEVICE_VER_RES - 28 - 32);
    lv_obj_set_pos(contact_list, 0, 28);
    lv_obj_set_style_bg_color(contact_list, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(contact_list, 0, 0);
    lv_obj_set_style_radius(contact_list, 0, 0);
    lv_obj_set_style_pad_all(contact_list, 2, 0);
    lv_obj_set_layout(contact_list, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(contact_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(contact_list, 2, 0);

    empty_label = lv_label_create(contact_list);
    lv_label_set_text(empty_label, "No contacts yet.\nGo to Contacts to add one.");
    lv_obj_set_style_text_color(empty_label, lv_color_hex(0x888888), 0);
    lv_obj_set_style_text_align(empty_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_set_width(empty_label, DEVICE_HOR_RES - 20);

    /* Bottom nav */
    lv_obj_t *nav = lv_obj_create(scr);
    lv_obj_set_size(nav, DEVICE_HOR_RES, 32);
    lv_obj_set_pos(nav, 0, DEVICE_VER_RES - 32);
    lv_obj_set_style_bg_color(nav, lv_color_hex(0x16213E), 0);
    lv_obj_set_style_border_width(nav, 0, 0);
    lv_obj_set_style_radius(nav, 0, 0);
    lv_obj_set_style_pad_all(nav, 2, 0);
    lv_obj_set_layout(nav, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(nav, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(nav, LV_FLEX_ALIGN_SPACE_EVENLY, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_scrollbar_mode(nav, LV_SCROLLBAR_MODE_OFF);

    static const char *nav_labels[] = {
        LV_SYMBOL_LIST " Contacts",
        LV_SYMBOL_EDIT " Compose",
        LV_SYMBOL_ENVELOPE " Inbox"
    };
    static lv_event_cb_t nav_cbs[] = { nav_contacts_cb, nav_compose_cb, nav_inbox_cb };

    for (int i = 0; i < 3; i++) {
        lv_obj_t *btn = lv_button_create(nav);
        lv_obj_set_size(btn, 98, 26);
        lv_obj_set_style_bg_color(btn, lv_color_hex(0x0F3460), 0);
        lv_obj_set_style_radius(btn, 4, 0);
        lv_obj_add_event_cb(btn, nav_cbs[i], LV_EVENT_CLICKED, NULL);

        lv_obj_t *lbl = lv_label_create(btn);
        lv_label_set_text(lbl, nav_labels[i]);
        lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, 0);
        lv_obj_set_style_text_color(lbl, lv_color_white(), 0);
        lv_obj_center(lbl);
    }
}

void scr_home_refresh(void)
{
    /* Update CA connection indicator */
    int ca_count = transport_connected_count(&g_app.transport);
    if (ca_count > 0) {
        char buf[16];
        snprintf(buf, sizeof(buf), LV_SYMBOL_OK " CA:%d", ca_count);
        lv_label_set_text(ca_status_lbl, buf);
        lv_obj_set_style_text_color(ca_status_lbl, lv_color_hex(0x00E676), 0);
    } else {
        lv_label_set_text(ca_status_lbl, LV_SYMBOL_CLOSE " CA");
        lv_obj_set_style_text_color(ca_status_lbl, lv_color_hex(0xFF1744), 0);
    }

    /* Clear dynamic children (keep empty_label) */
    uint32_t child_cnt = lv_obj_get_child_count(contact_list);
    for (int i = child_cnt - 1; i >= 0; i--) {
        lv_obj_t *child = lv_obj_get_child(contact_list, i);
        if (child != empty_label) lv_obj_delete(child);
    }

    if (g_app.contact_count == 0) {
        lv_obj_clear_flag(empty_label, LV_OBJ_FLAG_HIDDEN);
        return;
    }
    lv_obj_add_flag(empty_label, LV_OBJ_FLAG_HIDDEN);

    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        contact_t *c = &g_app.contacts[i];

        lv_obj_t *row = lv_obj_create(contact_list);
        lv_obj_set_size(row, LV_PCT(100), 36);
        lv_obj_set_style_bg_color(row, lv_color_hex(0x16213E), 0);
        lv_obj_set_style_radius(row, 4, 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_pad_all(row, 4, 0);
        lv_obj_set_scrollbar_mode(row, LV_SCROLLBAR_MODE_OFF);
        lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(row, contact_clicked_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)i);

        /* Status icon */
        const char *icon = (c->status == CONTACT_ESTABLISHED) ?
            LV_SYMBOL_OK : LV_SYMBOL_REFRESH;
        lv_color_t icon_color = (c->status == CONTACT_ESTABLISHED) ?
            lv_color_hex(0x00E676) : lv_color_hex(0xFFD600);

        lv_obj_t *ico = lv_label_create(row);
        lv_label_set_text(ico, icon);
        lv_obj_set_style_text_color(ico, icon_color, 0);
        lv_obj_set_style_text_font(ico, &lv_font_montserrat_12, 0);
        lv_obj_align(ico, LV_ALIGN_LEFT_MID, 0, 0);

        /* Contact name */
        lv_obj_t *name = lv_label_create(row);
        lv_label_set_text(name, c->name);
        lv_obj_set_style_text_color(name, lv_color_white(), 0);
        lv_obj_align(name, LV_ALIGN_LEFT_MID, 20, -6);

        /* Last message preview */
        message_t *last = messages_get_latest_for_contact(c->id);
        if (last) {
            lv_obj_t *preview = lv_label_create(row);
            char prev_text[48];
            snprintf(prev_text, sizeof(prev_text), "%s%.40s",
                     last->direction == MSG_SENT ? LV_SYMBOL_RIGHT " " : "",
                     last->plaintext);
            lv_label_set_text(preview, prev_text);
            lv_obj_set_style_text_color(preview, lv_color_hex(0x888888), 0);
            lv_obj_set_style_text_font(preview, &lv_font_montserrat_10, 0);
            lv_label_set_long_mode(preview, LV_LABEL_LONG_CLIP);
            lv_obj_set_width(preview, 240);
            lv_obj_align(preview, LV_ALIGN_LEFT_MID, 20, 6);
        }

        /* Unread badge */
        if (c->unread_count > 0) {
            lv_obj_t *badge = lv_label_create(row);
            char badge_text[16];
            snprintf(badge_text, sizeof(badge_text), "%u", c->unread_count);
            lv_label_set_text(badge, badge_text);
            lv_obj_set_style_text_color(badge, lv_color_white(), 0);
            lv_obj_set_style_text_font(badge, &lv_font_montserrat_10, 0);
            lv_obj_set_style_bg_color(badge, lv_color_hex(0xFF1744), 0);
            lv_obj_set_style_bg_opa(badge, LV_OPA_COVER, 0);
            lv_obj_set_style_radius(badge, 8, 0);
            lv_obj_set_style_pad_hor(badge, 5, 0);
            lv_obj_set_style_pad_ver(badge, 1, 0);
            lv_obj_align(badge, LV_ALIGN_RIGHT_MID, -4, 0);
        }
    }
}
