/**
 * Inbox Screen — Conversation list sorted by recency
 * Now includes status bar (top) and tab bar (bottom).
 */
#include "scr_inbox.h"
#include "scr_conversation.h"
#include "ui_common.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../data/messages.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *status_bar;
static lv_obj_t *tab_bar;
static lv_obj_t *list_cont;

static void convo_tap_cb(lv_event_t *e)
{
    uint32_t contact_id = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    g_app.selected_contact_id = contact_id;
    g_app.nav_back_screen = SCR_INBOX;
    contact_t *c = contacts_find_by_id(contact_id);
    if (c) {
        c->unread_count = 0;
        contacts_save();
    }
    app_navigate_to(SCR_CONVERSATION);
    scr_conversation_refresh();
}

/* Comparison for sorting: by latest message timestamp, descending */
typedef struct {
    uint32_t contact_id;
    time_t   latest_ts;
} convo_entry_t;

void scr_inbox_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_INBOX] = scr;
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1A2E), 0);

    /* Status bar at top */
    status_bar = ui_status_bar_create(scr);

    /* List — between status bar and tab bar */
    list_cont = lv_obj_create(scr);
    lv_obj_set_size(list_cont, DEVICE_HOR_RES, DEVICE_VER_RES - 20 - 32);
    lv_obj_set_pos(list_cont, 0, 20);
    lv_obj_set_style_bg_color(list_cont, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(list_cont, 0, 0);
    lv_obj_set_style_radius(list_cont, 0, 0);
    lv_obj_set_style_pad_all(list_cont, 4, 0);
    lv_obj_set_layout(list_cont, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(list_cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(list_cont, 3, 0);

    /* Tab bar at bottom */
    tab_bar = ui_tab_bar_create(scr, 1);  /* 1 = Inbox active */
}

void scr_inbox_refresh(void)
{
    ui_status_bar_refresh(status_bar);
    ui_tab_bar_refresh(tab_bar);
    lv_obj_clean(list_cont);

    /* Build list of contacts that have messages, sorted by latest */
    convo_entry_t entries[MAX_CONTACTS];
    uint32_t entry_count = 0;

    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        contact_t *c = &g_app.contacts[i];
        message_t *latest = messages_get_latest_for_contact(c->id);
        if (latest) {
            entries[entry_count].contact_id = c->id;
            entries[entry_count].latest_ts = latest->timestamp;
            entry_count++;
        }
    }

    /* Simple sort descending by timestamp */
    for (uint32_t i = 0; i < entry_count; i++) {
        for (uint32_t j = i + 1; j < entry_count; j++) {
            if (entries[j].latest_ts > entries[i].latest_ts) {
                convo_entry_t tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }

    if (entry_count == 0) {
        lv_obj_t *lbl = lv_label_create(list_cont);
        lv_label_set_text(lbl, "No conversations yet.\nSend or receive a message.");
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
        return;
    }

    for (uint32_t i = 0; i < entry_count; i++) {
        contact_t *c = contacts_find_by_id(entries[i].contact_id);
        if (!c) continue;
        message_t *latest = messages_get_latest_for_contact(c->id);

        lv_obj_t *row = lv_obj_create(list_cont);
        lv_obj_set_size(row, LV_PCT(100), 38);
        lv_obj_set_style_bg_color(row, lv_color_hex(0x16213E), 0);
        lv_obj_set_style_radius(row, 4, 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_pad_all(row, 4, 0);
        lv_obj_set_scrollbar_mode(row, LV_SCROLLBAR_MODE_OFF);
        lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(row, convo_tap_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)c->id);

        /* Contact name */
        lv_obj_t *name = lv_label_create(row);
        lv_label_set_text(name, c->name);
        lv_obj_set_style_text_color(name, lv_color_white(), 0);
        lv_obj_align(name, LV_ALIGN_TOP_LEFT, 0, 0);

        /* Message count */
        uint32_t msg_count = messages_count_for_contact(c->id);
        lv_obj_t *count_lbl = lv_label_create(row);
        lv_label_set_text_fmt(count_lbl, "%u msgs", msg_count);
        lv_obj_set_style_text_color(count_lbl, lv_color_hex(0x666666), 0);
        lv_obj_set_style_text_font(count_lbl, &lv_font_montserrat_10, 0);
        lv_obj_align(count_lbl, LV_ALIGN_TOP_RIGHT, -4, 0);

        /* Last message preview */
        if (latest) {
            lv_obj_t *preview = lv_label_create(row);
            char prev_text[MAX_TEXT_LEN + 8];
            snprintf(prev_text, sizeof(prev_text), "%s%s",
                     latest->direction == MSG_SENT ? "You: " : "",
                     latest->plaintext);
            lv_label_set_text(preview, prev_text);
            lv_obj_set_style_text_color(preview, lv_color_hex(0x999999), 0);
            lv_obj_set_style_text_font(preview, &lv_font_montserrat_10, 0);
            lv_label_set_long_mode(preview, LV_LABEL_LONG_CLIP);
            lv_obj_set_width(preview, DEVICE_HOR_RES - 60);
            lv_obj_align(preview, LV_ALIGN_BOTTOM_LEFT, 0, 0);
        }

        /* Unread badge */
        if (c->unread_count > 0) {
            lv_obj_t *badge = lv_label_create(row);
            lv_label_set_text_fmt(badge, "%u", c->unread_count);
            lv_obj_set_style_text_color(badge, lv_color_white(), 0);
            lv_obj_set_style_text_font(badge, &lv_font_montserrat_10, 0);
            lv_obj_set_style_bg_color(badge, lv_color_hex(0xFF1744), 0);
            lv_obj_set_style_bg_opa(badge, LV_OPA_COVER, 0);
            lv_obj_set_style_radius(badge, 8, 0);
            lv_obj_set_style_pad_hor(badge, 5, 0);
            lv_obj_set_style_pad_ver(badge, 1, 0);
            lv_obj_align(badge, LV_ALIGN_BOTTOM_RIGHT, -4, 0);
        }
    }
}
