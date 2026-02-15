/**
 * Conversation Screen — Threaded chat view for a single contact
 */
#include "scr_conversation.h"
#include "scr_inbox.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../data/messages.h"
#include "../crypto_sim.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *header_name;
static lv_obj_t *msg_list;
static lv_obj_t *reply_ta;
static lv_obj_t *send_btn;
static lv_obj_t *confirm_del_thread; /* confirmation dialog for thread delete */
static lv_obj_t *confirm_del_msg;    /* confirmation dialog for single message */
static uint32_t  pending_del_msg_id;

static void back_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_INBOX);
    scr_inbox_refresh();
}

static void send_reply_cb(lv_event_t *e)
{
    (void)e;
    const char *text = lv_textarea_get_text(reply_ta);
    if (!text || strlen(text) == 0) return;

    message_t *msg = messages_add(g_app.selected_contact_id, MSG_SENT, text);
    if (msg) {
        contact_t *c = contacts_find_by_id(g_app.selected_contact_id);
        if (c) {
            char ctx[128];
            snprintf(ctx, sizeof(ctx), "Encrypted Msg -> %s", c->name);
            app_log(ctx, msg->ciphertext);
        }
    }
    messages_save();
    lv_textarea_set_text(reply_ta, "");
    scr_conversation_refresh();
}

/* --- Delete thread --- */
static void delete_thread_ask_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_clear_flag(confirm_del_thread, LV_OBJ_FLAG_HIDDEN);
}

static void delete_thread_yes_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(confirm_del_thread, LV_OBJ_FLAG_HIDDEN);
    messages_delete_for_contact(g_app.selected_contact_id);
    messages_save();
    scr_conversation_refresh();
}

static void delete_thread_no_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(confirm_del_thread, LV_OBJ_FLAG_HIDDEN);
}

/* --- Delete single message --- */
static void msg_bubble_tap_cb(lv_event_t *e)
{
    pending_del_msg_id = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    lv_obj_clear_flag(confirm_del_msg, LV_OBJ_FLAG_HIDDEN);
}

static void delete_msg_yes_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(confirm_del_msg, LV_OBJ_FLAG_HIDDEN);
    messages_delete_by_id(pending_del_msg_id);
    messages_save();
    scr_conversation_refresh();
}

static void delete_msg_no_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(confirm_del_msg, LV_OBJ_FLAG_HIDDEN);
}

void scr_conversation_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_CONVERSATION] = scr;
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

    header_name = lv_label_create(header);
    lv_obj_set_style_text_color(header_name, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(header_name, &lv_font_montserrat_14, 0);
    lv_obj_align(header_name, LV_ALIGN_CENTER, 0, 0);

    /* Delete-thread button in header */
    lv_obj_t *del_thread_btn = lv_button_create(header);
    lv_obj_set_size(del_thread_btn, 28, 22);
    lv_obj_align(del_thread_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(del_thread_btn, lv_color_hex(0xFF1744), 0);
    lv_obj_set_style_radius(del_thread_btn, 4, 0);
    lv_obj_set_style_pad_all(del_thread_btn, 0, 0);
    lv_obj_add_event_cb(del_thread_btn, delete_thread_ask_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *dt_ico = lv_label_create(del_thread_btn);
    lv_label_set_text(dt_ico, LV_SYMBOL_TRASH);
    lv_obj_set_style_text_color(dt_ico, lv_color_white(), 0);
    lv_obj_set_style_text_font(dt_ico, &lv_font_montserrat_10, 0);
    lv_obj_center(dt_ico);

    /* Message list */
    msg_list = lv_obj_create(scr);
    lv_obj_set_size(msg_list, DEVICE_HOR_RES, DEVICE_VER_RES - 28 - 36);
    lv_obj_set_pos(msg_list, 0, 28);
    lv_obj_set_style_bg_color(msg_list, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(msg_list, 0, 0);
    lv_obj_set_style_radius(msg_list, 0, 0);
    lv_obj_set_style_pad_all(msg_list, 4, 0);
    lv_obj_set_layout(msg_list, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(msg_list, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(msg_list, 3, 0);

    /* Reply bar at bottom */
    lv_obj_t *reply_bar = lv_obj_create(scr);
    lv_obj_set_size(reply_bar, DEVICE_HOR_RES, 36);
    lv_obj_set_pos(reply_bar, 0, DEVICE_VER_RES - 36);
    lv_obj_set_style_bg_color(reply_bar, lv_color_hex(0x16213E), 0);
    lv_obj_set_style_border_width(reply_bar, 0, 0);
    lv_obj_set_style_radius(reply_bar, 0, 0);
    lv_obj_set_style_pad_all(reply_bar, 3, 0);
    lv_obj_set_scrollbar_mode(reply_bar, LV_SCROLLBAR_MODE_OFF);

    reply_ta = lv_textarea_create(reply_bar);
    lv_obj_set_size(reply_ta, DEVICE_HOR_RES - 60, 28);
    lv_obj_align(reply_ta, LV_ALIGN_LEFT_MID, 0, 0);
    lv_textarea_set_one_line(reply_ta, true);
    lv_textarea_set_placeholder_text(reply_ta, "Reply...");
    if (g_app.dev_group) lv_group_add_obj(g_app.dev_group, reply_ta);

    send_btn = lv_button_create(reply_bar);
    lv_obj_set_size(send_btn, 48, 28);
    lv_obj_align(send_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(send_btn, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(send_btn, send_reply_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *slbl = lv_label_create(send_btn);
    lv_label_set_text(slbl, LV_SYMBOL_OK);
    lv_obj_set_style_text_color(slbl, lv_color_white(), 0);
    lv_obj_center(slbl);

    /* --- Delete thread confirmation dialog --- */
    confirm_del_thread = lv_obj_create(scr);
    lv_obj_set_size(confirm_del_thread, 260, 90);
    lv_obj_center(confirm_del_thread);
    lv_obj_set_style_bg_color(confirm_del_thread, lv_color_hex(0x0F3460), 0);
    lv_obj_set_style_border_color(confirm_del_thread, lv_color_hex(0xFF1744), 0);
    lv_obj_set_style_border_width(confirm_del_thread, 2, 0);
    lv_obj_set_style_radius(confirm_del_thread, 8, 0);
    lv_obj_set_style_pad_all(confirm_del_thread, 8, 0);
    lv_obj_add_flag(confirm_del_thread, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *dt_prompt = lv_label_create(confirm_del_thread);
    lv_label_set_text(dt_prompt, "Delete all messages\nin this conversation?");
    lv_obj_set_style_text_color(dt_prompt, lv_color_white(), 0);
    lv_obj_align(dt_prompt, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t *dt_yes = lv_button_create(confirm_del_thread);
    lv_obj_set_size(dt_yes, 80, 26);
    lv_obj_align(dt_yes, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(dt_yes, lv_color_hex(0xFF1744), 0);
    lv_obj_add_event_cb(dt_yes, delete_thread_yes_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *dt_yes_lbl = lv_label_create(dt_yes);
    lv_label_set_text(dt_yes_lbl, "Delete");
    lv_obj_set_style_text_color(dt_yes_lbl, lv_color_white(), 0);
    lv_obj_center(dt_yes_lbl);

    lv_obj_t *dt_no = lv_button_create(confirm_del_thread);
    lv_obj_set_size(dt_no, 80, 26);
    lv_obj_align(dt_no, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(dt_no, lv_color_hex(0x424242), 0);
    lv_obj_add_event_cb(dt_no, delete_thread_no_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *dt_no_lbl = lv_label_create(dt_no);
    lv_label_set_text(dt_no_lbl, "Cancel");
    lv_obj_set_style_text_color(dt_no_lbl, lv_color_white(), 0);
    lv_obj_center(dt_no_lbl);

    /* --- Delete single message confirmation dialog --- */
    confirm_del_msg = lv_obj_create(scr);
    lv_obj_set_size(confirm_del_msg, 240, 80);
    lv_obj_center(confirm_del_msg);
    lv_obj_set_style_bg_color(confirm_del_msg, lv_color_hex(0x0F3460), 0);
    lv_obj_set_style_border_color(confirm_del_msg, lv_color_hex(0xFF9100), 0);
    lv_obj_set_style_border_width(confirm_del_msg, 2, 0);
    lv_obj_set_style_radius(confirm_del_msg, 8, 0);
    lv_obj_set_style_pad_all(confirm_del_msg, 8, 0);
    lv_obj_add_flag(confirm_del_msg, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *dm_prompt = lv_label_create(confirm_del_msg);
    lv_label_set_text(dm_prompt, "Delete this message?");
    lv_obj_set_style_text_color(dm_prompt, lv_color_white(), 0);
    lv_obj_align(dm_prompt, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t *dm_yes = lv_button_create(confirm_del_msg);
    lv_obj_set_size(dm_yes, 80, 26);
    lv_obj_align(dm_yes, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(dm_yes, lv_color_hex(0xFF1744), 0);
    lv_obj_add_event_cb(dm_yes, delete_msg_yes_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *dm_yes_lbl = lv_label_create(dm_yes);
    lv_label_set_text(dm_yes_lbl, "Delete");
    lv_obj_set_style_text_color(dm_yes_lbl, lv_color_white(), 0);
    lv_obj_center(dm_yes_lbl);

    lv_obj_t *dm_no = lv_button_create(confirm_del_msg);
    lv_obj_set_size(dm_no, 80, 26);
    lv_obj_align(dm_no, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(dm_no, lv_color_hex(0x424242), 0);
    lv_obj_add_event_cb(dm_no, delete_msg_no_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *dm_no_lbl = lv_label_create(dm_no);
    lv_label_set_text(dm_no_lbl, "Cancel");
    lv_obj_set_style_text_color(dm_no_lbl, lv_color_white(), 0);
    lv_obj_center(dm_no_lbl);
}

void scr_conversation_refresh(void)
{
    contact_t *c = contacts_find_by_id(g_app.selected_contact_id);
    if (c) {
        lv_label_set_text_fmt(header_name, LV_SYMBOL_EYE_CLOSE " %s", c->name);
        c->unread_count = 0;
    } else {
        lv_label_set_text(header_name, "Conversation");
    }

    lv_obj_clean(msg_list);

    for (uint32_t i = 0; i < g_app.message_count; i++) {
        message_t *m = &g_app.messages[i];
        if (m->contact_id != g_app.selected_contact_id) continue;

        bool is_sent = (m->direction == MSG_SENT);

        lv_obj_t *bubble = lv_obj_create(msg_list);
        lv_obj_set_width(bubble, LV_PCT(85));
        lv_obj_set_height(bubble, LV_SIZE_CONTENT);
        lv_obj_set_style_radius(bubble, 8, 0);
        lv_obj_set_style_border_width(bubble, 0, 0);
        lv_obj_set_style_pad_all(bubble, 6, 0);
        lv_obj_set_scrollbar_mode(bubble, LV_SCROLLBAR_MODE_OFF);
        lv_obj_add_flag(bubble, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(bubble, msg_bubble_tap_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)m->id);

        if (is_sent) {
            lv_obj_set_style_bg_color(bubble, lv_color_hex(0x0F3460), 0);
            lv_obj_set_flex_align(msg_list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_END, LV_FLEX_ALIGN_END);
        } else {
            lv_obj_set_style_bg_color(bubble, lv_color_hex(0x2D2D44), 0);
            lv_obj_set_flex_align(msg_list, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_START);
        }

        /* Direction indicator */
        lv_obj_t *dir_lbl = lv_label_create(bubble);
        lv_label_set_text(dir_lbl, is_sent ? LV_SYMBOL_RIGHT " You" : LV_SYMBOL_LEFT " Them");
        lv_obj_set_style_text_color(dir_lbl, is_sent ? lv_color_hex(0x00B0FF) : lv_color_hex(0xFF9100), 0);
        lv_obj_set_style_text_font(dir_lbl, &lv_font_montserrat_10, 0);
        lv_obj_align(dir_lbl, LV_ALIGN_TOP_LEFT, 0, 0);

        /* Message text */
        lv_obj_t *text = lv_label_create(bubble);
        lv_label_set_text(text, m->plaintext);
        lv_obj_set_style_text_color(text, lv_color_white(), 0);
        lv_obj_set_width(text, LV_PCT(100));
        lv_label_set_long_mode(text, LV_LABEL_LONG_WRAP);
        lv_obj_align(text, LV_ALIGN_TOP_LEFT, 0, 14);

        /* Resize bubble to fit content */
        lv_obj_update_layout(text);
        int32_t text_h = lv_obj_get_height(text);
        lv_obj_set_height(bubble, text_h + 24);
    }

    /* Scroll to bottom */
    lv_obj_scroll_to_y(msg_list, LV_COORD_MAX, LV_ANIM_OFF);
}
