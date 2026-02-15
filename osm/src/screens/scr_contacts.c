/**
 * Contacts Screen — Manage contacts + initiate key exchange
 */
#include "scr_contacts.h"
#include "scr_key_exchange.h"
#include "scr_home.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../data/messages.h"
#include "../crypto.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *list_cont;
static lv_obj_t *name_input_cont;
static lv_obj_t *name_ta;
static lv_obj_t *confirm_del_cont;     /* delete-contact confirmation dialog */
static uint32_t  pending_delete_id;    /* contact id awaiting confirmation */

static void back_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_HOME);
    scr_home_refresh();
}

static void add_contact_confirm_cb(lv_event_t *e)
{
    (void)e;
    const char *name = lv_textarea_get_text(name_ta);
    if (name && strlen(name) > 0) {
        contact_t *c = contacts_add(name);
        if (c) {
            /* Store our pubkey as the key to send to the peer */
            crypto_pubkey_to_b64(g_app.identity.pubkey,
                                 c->public_key, MAX_KEY_LEN);
            c->status = CONTACT_PENDING_SENT;
            contacts_save();

            /* Log DH key output */
            {
                char ctx[128];
                snprintf(ctx, sizeof(ctx), "DH Key -> %s (initiated)", c->name);
                app_log(ctx, c->public_key);
            }

            /* Navigate to key exchange wizard */
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

static void delete_contact_ask_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        pending_delete_id = g_app.contacts[idx].id;
        /* Update confirmation label with contact name */
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

static void contact_tap_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx < g_app.contact_count) {
        g_app.selected_contact_id = g_app.contacts[idx].id;
        app_navigate_to(SCR_KEY_EXCHANGE);
        scr_key_exchange_refresh();
    }
}

void scr_contacts_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_CONTACTS] = scr;
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
    lv_obj_t *back_lbl = lv_label_create(back_btn);
    lv_label_set_text(back_lbl, LV_SYMBOL_LEFT);
    lv_obj_set_style_text_color(back_lbl, lv_color_white(), 0);
    lv_obj_center(back_lbl);

    lv_obj_t *title = lv_label_create(header);
    lv_label_set_text(title, "Contacts");
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);

    lv_obj_t *add_btn = lv_button_create(header);
    lv_obj_set_size(add_btn, 40, 22);
    lv_obj_align(add_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(add_btn, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(add_btn, add_contact_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *add_lbl = lv_label_create(add_btn);
    lv_label_set_text(add_lbl, LV_SYMBOL_PLUS);
    lv_obj_set_style_text_color(add_lbl, lv_color_white(), 0);
    lv_obj_center(add_lbl);

    /* Contact list area */
    list_cont = lv_obj_create(scr);
    lv_obj_set_size(list_cont, DEVICE_HOR_RES, DEVICE_VER_RES - 28);
    lv_obj_set_pos(list_cont, 0, 28);
    lv_obj_set_style_bg_color(list_cont, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(list_cont, 0, 0);
    lv_obj_set_style_radius(list_cont, 0, 0);
    lv_obj_set_style_pad_all(list_cont, 4, 0);
    lv_obj_set_layout(list_cont, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(list_cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(list_cont, 3, 0);

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

    lv_obj_t *ok_btn = lv_button_create(name_input_cont);
    lv_obj_set_size(ok_btn, 80, 26);
    lv_obj_align(ok_btn, LV_ALIGN_BOTTOM_RIGHT, 0, 0);
    lv_obj_set_style_bg_color(ok_btn, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(ok_btn, add_contact_confirm_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *ok_lbl = lv_label_create(ok_btn);
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
        lv_obj_align(ico, LV_ALIGN_LEFT_MID, 0, 0);

        lv_obj_t *name = lv_label_create(row);
        lv_label_set_text(name, c->name);
        lv_obj_set_style_text_color(name, lv_color_white(), 0);
        lv_obj_align(name, LV_ALIGN_LEFT_MID, 22, 0);

        /* Status text */
        const char *st_label;
        switch (c->status) {
        case CONTACT_ESTABLISHED:  st_label = "Secure"; break;
        case CONTACT_PENDING_SENT: st_label = "Awaiting reply"; break;
        case CONTACT_PENDING_RECEIVED: st_label = "Action needed"; break;
        default: st_label = "";
        }
        lv_obj_t *st = lv_label_create(row);
        lv_label_set_text(st, st_label);
        lv_obj_set_style_text_color(st, lv_color_hex(0x888888), 0);
        lv_obj_set_style_text_font(st, &lv_font_montserrat_10, 0);
        lv_obj_align(st, LV_ALIGN_RIGHT_MID, -30, 0);

        /* Delete button */
        lv_obj_t *del_btn = lv_button_create(row);
        lv_obj_set_size(del_btn, 24, 22);
        lv_obj_align(del_btn, LV_ALIGN_RIGHT_MID, 0, 0);
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
    }
}
