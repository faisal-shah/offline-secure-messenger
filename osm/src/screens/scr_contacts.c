/**
 * Contacts Screen — Manage contacts + initiate key exchange
 * Now includes status bar (top) and tab bar (bottom).
 */
#include "scr_contacts.h"
#include "scr_key_exchange.h"
#include "scr_conversation.h"
#include "ui_common.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../data/messages.h"
#include "../crypto.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *status_bar;
static lv_obj_t *tab_bar;
static lv_obj_t *list_cont;
static lv_obj_t *name_input_cont;
static lv_obj_t *name_ta;
static lv_obj_t *add_btn_hdr;
static lv_obj_t *ok_btn_dialog;
static lv_obj_t *confirm_del_cont;
static uint32_t  pending_delete_id;

/* Rename dialog */
static lv_obj_t *rename_input_cont;
static lv_obj_t *rename_ta;
static uint32_t  rename_contact_id;

static void add_contact_confirm_cb(lv_event_t *e)
{
    (void)e;
    const char *name = lv_textarea_get_text(name_ta);
    if (name && strlen(name) > 0) {
        contact_t *c = contacts_add(name);
        if (c) {
            crypto_pubkey_to_b64(g_app.identity.pubkey,
                                 c->public_key, MAX_KEY_LEN);
            c->status = CONTACT_PENDING_SENT;
            contacts_save();
            app_send_key_exchange(c->public_key);
            {
                char ctx[128];
                snprintf(ctx, sizeof(ctx), "DH Key -> %s (initiated)", c->name);
                app_log(ctx, c->public_key);
            }
            g_app.selected_contact_id = c->id;
            app_navigate_to(SCR_KEY_EXCHANGE);
            scr_key_exchange_refresh();
        }
    }
    lv_obj_add_flag(name_input_cont, LV_OBJ_FLAG_HIDDEN);
}

static void add_contact_cb(lv_event_t *e)
{
    (void)e;
    lv_textarea_set_text(name_ta, "");
    lv_obj_clear_flag(name_input_cont, LV_OBJ_FLAG_HIDDEN);
}

static void cancel_add_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(name_input_cont, LV_OBJ_FLAG_HIDDEN);
}

/* Delete contact */
static void delete_contact_ask_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        pending_delete_id = g_app.contacts[idx].id;
        lv_obj_t *lbl = lv_obj_get_child(confirm_del_cont, 0);
        char msg[128];
        snprintf(msg, sizeof(msg), "Delete \"%s\"?\nAll messages will be removed.",
                 g_app.contacts[idx].name);
        lv_label_set_text(lbl, msg);
        lv_obj_clear_flag(confirm_del_cont, LV_OBJ_FLAG_HIDDEN);
    }
}

static void delete_contact_yes_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(confirm_del_cont, LV_OBJ_FLAG_HIDDEN);
    messages_delete_for_contact(pending_delete_id);
    contacts_delete(pending_delete_id);
    contacts_save();
    messages_save();
    scr_contacts_refresh();
}

static void delete_contact_no_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(confirm_del_cont, LV_OBJ_FLAG_HIDDEN);
}

/* Rename contact */
static void rename_ask_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        rename_contact_id = g_app.contacts[idx].id;
        lv_textarea_set_text(rename_ta, g_app.contacts[idx].name);
        lv_obj_clear_flag(rename_input_cont, LV_OBJ_FLAG_HIDDEN);
    }
}

static void rename_confirm_cb(lv_event_t *e)
{
    (void)e;
    const char *new_name = lv_textarea_get_text(rename_ta);
    if (new_name && strlen(new_name) > 0) {
        contact_t *c = contacts_find_by_id(rename_contact_id);
        if (c) {
            strncpy(c->name, new_name, MAX_NAME_LEN - 1);
            c->name[MAX_NAME_LEN - 1] = '\0';
            contacts_save();
        }
    }
    lv_obj_add_flag(rename_input_cont, LV_OBJ_FLAG_HIDDEN);
    scr_contacts_refresh();
}

static void rename_cancel_cb(lv_event_t *e)
{
    (void)e;
    lv_obj_add_flag(rename_input_cont, LV_OBJ_FLAG_HIDDEN);
}

/* Tap contact row: established → conversation, pending → key exchange */
static void contact_tap_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        contact_t *c = &g_app.contacts[idx];
        g_app.selected_contact_id = c->id;
        if (c->status == CONTACT_ESTABLISHED) {
            g_app.nav_back_screen = SCR_CONTACTS;
            c->unread_count = 0;
            contacts_save();
            app_navigate_to(SCR_CONVERSATION);
            scr_conversation_refresh();
        } else {
            app_navigate_to(SCR_KEY_EXCHANGE);
            scr_key_exchange_refresh();
        }
    }
}

/* Message button on a contact row — go directly to conversation */
static void message_btn_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        contact_t *c = &g_app.contacts[idx];
        g_app.selected_contact_id = c->id;
        g_app.nav_back_screen = SCR_CONTACTS;
        c->unread_count = 0;
        contacts_save();
        app_navigate_to(SCR_CONVERSATION);
        scr_conversation_refresh();
    }
}

void scr_contacts_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_CONTACTS] = scr;
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x1A1A2E), 0);

    /* Status bar at top */
    status_bar = ui_status_bar_create(scr);

    /* Add button (positioned right of status bar) */
    add_btn_hdr = lv_button_create(status_bar);
    lv_obj_set_size(add_btn_hdr, 20, 16);
    lv_obj_align(add_btn_hdr, LV_ALIGN_RIGHT_MID, -90, 0);
    lv_obj_set_style_bg_color(add_btn_hdr, lv_color_hex(0x00C853), 0);
    lv_obj_set_style_radius(add_btn_hdr, 4, 0);
    lv_obj_set_style_pad_all(add_btn_hdr, 0, 0);
    lv_obj_add_event_cb(add_btn_hdr, add_contact_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *add_lbl = lv_label_create(add_btn_hdr);
    lv_label_set_text(add_lbl, LV_SYMBOL_PLUS);
    lv_obj_set_style_text_color(add_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(add_lbl, &lv_font_montserrat_10, 0);
    lv_obj_center(add_lbl);

    /* Contact list area — between status bar and tab bar */
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
    tab_bar = ui_tab_bar_create(scr, 0);  /* 0 = Contacts active */

    /* Name input overlay (hidden by default) */
    name_input_cont = lv_obj_create(scr);
    lv_obj_set_size(name_input_cont, 280, 100);
    lv_obj_center(name_input_cont);
    lv_obj_set_style_bg_color(name_input_cont, lv_color_hex(0x0F3460), 0);
    lv_obj_set_style_border_color(name_input_cont, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_border_width(name_input_cont, 2, 0);
    lv_obj_set_style_radius(name_input_cont, 8, 0);
    lv_obj_set_style_pad_all(name_input_cont, 8, 0);
    lv_obj_add_flag(name_input_cont, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *prompt = lv_label_create(name_input_cont);
    lv_label_set_text(prompt, "New Contact Name:");
    lv_obj_set_style_text_color(prompt, lv_color_white(), 0);
    lv_obj_align(prompt, LV_ALIGN_TOP_LEFT, 0, 0);

    name_ta = lv_textarea_create(name_input_cont);
    lv_obj_set_size(name_ta, 260, 30);
    lv_obj_align(name_ta, LV_ALIGN_TOP_LEFT, 0, 20);
    lv_textarea_set_one_line(name_ta, true);
    lv_textarea_set_placeholder_text(name_ta, "Enter name...");
    if (g_app.dev_group) lv_group_add_obj(g_app.dev_group, name_ta);

    ok_btn_dialog = lv_button_create(name_input_cont);
    lv_obj_set_size(ok_btn_dialog, 80, 26);
    lv_obj_align(ok_btn_dialog, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(ok_btn_dialog, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(ok_btn_dialog, add_contact_confirm_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *ok_lbl = lv_label_create(ok_btn_dialog);
    lv_label_set_text(ok_lbl, "Create");
    lv_obj_set_style_text_color(ok_lbl, lv_color_white(), 0);
    lv_obj_center(ok_lbl);

    lv_obj_t *cancel_btn = lv_button_create(name_input_cont);
    lv_obj_set_size(cancel_btn, 80, 26);
    lv_obj_align(cancel_btn, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(cancel_btn, lv_color_hex(0x424242), 0);
    lv_obj_add_event_cb(cancel_btn, cancel_add_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *cancel_lbl = lv_label_create(cancel_btn);
    lv_label_set_text(cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(cancel_lbl, lv_color_white(), 0);
    lv_obj_center(cancel_lbl);

    /* Rename dialog (hidden by default) */
    rename_input_cont = lv_obj_create(scr);
    lv_obj_set_size(rename_input_cont, 280, 100);
    lv_obj_center(rename_input_cont);
    lv_obj_set_style_bg_color(rename_input_cont, lv_color_hex(0x0F3460), 0);
    lv_obj_set_style_border_color(rename_input_cont, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_border_width(rename_input_cont, 2, 0);
    lv_obj_set_style_radius(rename_input_cont, 8, 0);
    lv_obj_set_style_pad_all(rename_input_cont, 8, 0);
    lv_obj_add_flag(rename_input_cont, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *ren_prompt = lv_label_create(rename_input_cont);
    lv_label_set_text(ren_prompt, "Rename Contact:");
    lv_obj_set_style_text_color(ren_prompt, lv_color_white(), 0);
    lv_obj_align(ren_prompt, LV_ALIGN_TOP_LEFT, 0, 0);

    rename_ta = lv_textarea_create(rename_input_cont);
    lv_obj_set_size(rename_ta, 260, 30);
    lv_obj_align(rename_ta, LV_ALIGN_TOP_LEFT, 0, 20);
    lv_textarea_set_one_line(rename_ta, true);
    if (g_app.dev_group) lv_group_add_obj(g_app.dev_group, rename_ta);

    lv_obj_t *ren_ok = lv_button_create(rename_input_cont);
    lv_obj_set_size(ren_ok, 80, 26);
    lv_obj_align(ren_ok, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(ren_ok, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(ren_ok, rename_confirm_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *ren_ok_lbl = lv_label_create(ren_ok);
    lv_label_set_text(ren_ok_lbl, "Save");
    lv_obj_set_style_text_color(ren_ok_lbl, lv_color_white(), 0);
    lv_obj_center(ren_ok_lbl);

    lv_obj_t *ren_cancel = lv_button_create(rename_input_cont);
    lv_obj_set_size(ren_cancel, 80, 26);
    lv_obj_align(ren_cancel, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(ren_cancel, lv_color_hex(0x424242), 0);
    lv_obj_add_event_cb(ren_cancel, rename_cancel_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *ren_cancel_lbl = lv_label_create(ren_cancel);
    lv_label_set_text(ren_cancel_lbl, "Cancel");
    lv_obj_set_style_text_color(ren_cancel_lbl, lv_color_white(), 0);
    lv_obj_center(ren_cancel_lbl);

    /* Delete confirmation dialog (hidden by default) */
    confirm_del_cont = lv_obj_create(scr);
    lv_obj_set_size(confirm_del_cont, 280, 110);
    lv_obj_center(confirm_del_cont);
    lv_obj_set_style_bg_color(confirm_del_cont, lv_color_hex(0x0F3460), 0);
    lv_obj_set_style_border_color(confirm_del_cont, lv_color_hex(0xFF1744), 0);
    lv_obj_set_style_border_width(confirm_del_cont, 2, 0);
    lv_obj_set_style_radius(confirm_del_cont, 8, 0);
    lv_obj_set_style_pad_all(confirm_del_cont, 8, 0);
    lv_obj_add_flag(confirm_del_cont, LV_OBJ_FLAG_HIDDEN);

    lv_obj_t *del_prompt = lv_label_create(confirm_del_cont);
    lv_label_set_text(del_prompt, "");
    lv_obj_set_style_text_color(del_prompt, lv_color_white(), 0);
    lv_obj_set_width(del_prompt, 260);
    lv_label_set_long_mode(del_prompt, LV_LABEL_LONG_WRAP);
    lv_obj_align(del_prompt, LV_ALIGN_TOP_LEFT, 0, 0);

    lv_obj_t *del_yes = lv_button_create(confirm_del_cont);
    lv_obj_set_size(del_yes, 80, 26);
    lv_obj_align(del_yes, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(del_yes, lv_color_hex(0xFF1744), 0);
    lv_obj_add_event_cb(del_yes, delete_contact_yes_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *del_yes_lbl = lv_label_create(del_yes);
    lv_label_set_text(del_yes_lbl, "Delete");
    lv_obj_set_style_text_color(del_yes_lbl, lv_color_white(), 0);
    lv_obj_center(del_yes_lbl);

    lv_obj_t *del_no = lv_button_create(confirm_del_cont);
    lv_obj_set_size(del_no, 80, 26);
    lv_obj_align(del_no, LV_ALIGN_BOTTOM_LEFT, 0, 0);
    lv_obj_set_style_bg_color(del_no, lv_color_hex(0x424242), 0);
    lv_obj_add_event_cb(del_no, delete_contact_no_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *del_no_lbl = lv_label_create(del_no);
    lv_label_set_text(del_no_lbl, "Cancel");
    lv_obj_set_style_text_color(del_no_lbl, lv_color_white(), 0);
    lv_obj_center(del_no_lbl);
}

void scr_contacts_refresh(void)
{
    ui_status_bar_refresh(status_bar);
    ui_tab_bar_refresh(tab_bar);
    lv_obj_clean(list_cont);

    if (g_app.contact_count == 0) {
        lv_obj_t *lbl = lv_label_create(list_cont);
        lv_label_set_text(lbl, "No contacts.\nTap " LV_SYMBOL_PLUS " to add one.");
        lv_obj_set_style_text_color(lbl, lv_color_hex(0x888888), 0);
        return;
    }

    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        contact_t *c = &g_app.contacts[i];

        lv_obj_t *row = lv_obj_create(list_cont);
        lv_obj_set_size(row, LV_PCT(100), 32);
        lv_obj_set_style_bg_color(row, lv_color_hex(0x16213E), 0);
        lv_obj_set_style_radius(row, 4, 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_pad_all(row, 4, 0);
        lv_obj_set_scrollbar_mode(row, LV_SCROLLBAR_MODE_OFF);
        lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(row, contact_tap_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)i);

        /* Status icon */
        const char *status_text;
        lv_color_t status_color;
        switch (c->status) {
        case CONTACT_ESTABLISHED:
            status_text = LV_SYMBOL_OK;
            status_color = lv_color_hex(0x00E676);
            break;
        case CONTACT_PENDING_SENT:
            status_text = LV_SYMBOL_UPLOAD;
            status_color = lv_color_hex(0xFFD600);
            break;
        case CONTACT_PENDING_RECEIVED:
            status_text = LV_SYMBOL_DOWNLOAD;
            status_color = lv_color_hex(0xFF9100);
            break;
        default:
            status_text = "?";
            status_color = lv_color_hex(0x888888);
        }

        lv_obj_t *ico = lv_label_create(row);
        lv_label_set_text(ico, status_text);
        lv_obj_set_style_text_color(ico, status_color, 0);
        lv_obj_set_style_text_font(ico, &lv_font_montserrat_10, 0);
        lv_obj_align(ico, LV_ALIGN_LEFT_MID, 0, 0);

        lv_obj_t *name = lv_label_create(row);
        lv_label_set_text(name, c->name);
        lv_obj_set_style_text_color(name, lv_color_white(), 0);
        lv_obj_set_style_text_font(name, &lv_font_montserrat_12, 0);
        lv_obj_align(name, LV_ALIGN_LEFT_MID, 16, 0);

        /* Action buttons — right side of row */
        int btn_x = -2;

        /* Delete button (always) */
        lv_obj_t *del_btn = lv_button_create(row);
        lv_obj_set_size(del_btn, 22, 20);
        lv_obj_align(del_btn, LV_ALIGN_RIGHT_MID, btn_x, 0);
        lv_obj_set_style_bg_color(del_btn, lv_color_hex(0xFF1744), 0);
        lv_obj_set_style_radius(del_btn, 4, 0);
        lv_obj_set_style_pad_all(del_btn, 0, 0);
        lv_obj_add_event_cb(del_btn, delete_contact_ask_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)i);
        lv_obj_t *del_ico = lv_label_create(del_btn);
        lv_label_set_text(del_ico, LV_SYMBOL_TRASH);
        lv_obj_set_style_text_color(del_ico, lv_color_white(), 0);
        lv_obj_set_style_text_font(del_ico, &lv_font_montserrat_10, 0);
        lv_obj_center(del_ico);
        btn_x -= 26;

        /* Edit/rename button (always) */
        lv_obj_t *edit_btn = lv_button_create(row);
        lv_obj_set_size(edit_btn, 22, 20);
        lv_obj_align(edit_btn, LV_ALIGN_RIGHT_MID, btn_x, 0);
        lv_obj_set_style_bg_color(edit_btn, lv_color_hex(0x0F3460), 0);
        lv_obj_set_style_radius(edit_btn, 4, 0);
        lv_obj_set_style_pad_all(edit_btn, 0, 0);
        lv_obj_add_event_cb(edit_btn, rename_ask_cb, LV_EVENT_CLICKED,
                            (void *)(uintptr_t)i);
        lv_obj_t *edit_ico = lv_label_create(edit_btn);
        lv_label_set_text(edit_ico, LV_SYMBOL_EDIT);
        lv_obj_set_style_text_color(edit_ico, lv_color_white(), 0);
        lv_obj_set_style_text_font(edit_ico, &lv_font_montserrat_10, 0);
        lv_obj_center(edit_ico);
        btn_x -= 26;

        /* Message button (only for established contacts) */
        if (c->status == CONTACT_ESTABLISHED) {
            lv_obj_t *msg_btn = lv_button_create(row);
            lv_obj_set_size(msg_btn, 22, 20);
            lv_obj_align(msg_btn, LV_ALIGN_RIGHT_MID, btn_x, 0);
            lv_obj_set_style_bg_color(msg_btn, lv_color_hex(0x00C853), 0);
            lv_obj_set_style_radius(msg_btn, 4, 0);
            lv_obj_set_style_pad_all(msg_btn, 0, 0);
            lv_obj_add_event_cb(msg_btn, message_btn_cb, LV_EVENT_CLICKED,
                                (void *)(uintptr_t)i);
            lv_obj_t *msg_ico = lv_label_create(msg_btn);
            lv_label_set_text(msg_ico, LV_SYMBOL_ENVELOPE);
            lv_obj_set_style_text_color(msg_ico, lv_color_white(), 0);
            lv_obj_set_style_text_font(msg_ico, &lv_font_montserrat_10, 0);
            lv_obj_center(msg_ico);
        }
    }
}

lv_obj_t *scr_contacts_get_add_btn(void) { return add_btn_hdr; }
lv_obj_t *scr_contacts_get_name_ta(void) { return name_ta; }
lv_obj_t *scr_contacts_get_name_ok_btn(void) { return ok_btn_dialog; }
