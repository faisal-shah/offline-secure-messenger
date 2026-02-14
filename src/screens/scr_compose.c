/**
 * Compose Screen — Write and send encrypted message
 */
#include "scr_compose.h"
#include "scr_home.h"
#include "scr_conversation.h"
#include "../app.h"
#include "../data/contacts.h"
#include "../data/messages.h"
#include "../crypto_sim.h"
#include "../io_monitor.h"
#include <stdio.h>
#include <string.h>

static lv_obj_t *contact_dd;
static lv_obj_t *msg_ta;
static lv_obj_t *send_btn;
static lv_obj_t *status_lbl;
static lv_obj_t *char_count_lbl;

/* Map dropdown index → contact index (only established contacts) */
static uint32_t dd_to_contact[MAX_CONTACTS];
static uint32_t dd_count;

static void back_cb(lv_event_t *e)
{
    (void)e;
    app_navigate_to(SCR_HOME);
    scr_home_refresh();
}

static void ta_changed_cb(lv_event_t *e)
{
    (void)e;
    const char *text = lv_textarea_get_text(msg_ta);
    size_t len = text ? strlen(text) : 0;
    lv_label_set_text_fmt(char_count_lbl, "%u/%d", (unsigned)len, MAX_TEXT_LEN - 1);
}

static void send_cb(lv_event_t *e)
{
    (void)e;
    uint32_t sel = lv_dropdown_get_selected(contact_dd);
    if (sel >= dd_count) return;

    const char *text = lv_textarea_get_text(msg_ta);
    if (!text || strlen(text) == 0) {
        lv_label_set_text(status_lbl, "Type a message first!");
        lv_obj_set_style_text_color(status_lbl, lv_color_hex(0xFF1744), 0);
        return;
    }

    uint32_t contact_idx = dd_to_contact[sel];
    contact_t *c = &g_app.contacts[contact_idx];

    message_t *msg = messages_add(c->id, MSG_SENT, text);
    if (msg) {
        messages_save();

        /* Log to I/O monitor */
        char ctx[128];
        snprintf(ctx, sizeof(ctx), "Encrypted Msg " LV_SYMBOL_RIGHT " %s", c->name);
        io_monitor_log(ctx, msg->ciphertext);

        char status_text[128];
        snprintf(status_text, sizeof(status_text),
                 LV_SYMBOL_OK " Sent to %s\n(%.20s...)", c->name, msg->ciphertext);
        lv_label_set_text(status_lbl, status_text);
        lv_obj_set_style_text_color(status_lbl, lv_color_hex(0x00E676), 0);

        lv_textarea_set_text(msg_ta, "");
    }
}

void scr_compose_create(void)
{
    lv_obj_t *scr = lv_obj_create(NULL);
    g_app.screens[SCR_COMPOSE] = scr;
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
    lv_label_set_text(title, LV_SYMBOL_EDIT " Compose");
    lv_obj_set_style_text_color(title, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, 0);

    /* Body */
    lv_obj_t *body = lv_obj_create(scr);
    lv_obj_set_size(body, DEVICE_HOR_RES, DEVICE_VER_RES - 28);
    lv_obj_set_pos(body, 0, 28);
    lv_obj_set_style_bg_color(body, lv_color_hex(0x1A1A2E), 0);
    lv_obj_set_style_border_width(body, 0, 0);
    lv_obj_set_style_radius(body, 0, 0);
    lv_obj_set_style_pad_all(body, 6, 0);
    lv_obj_set_scrollbar_mode(body, LV_SCROLLBAR_MODE_OFF);

    /* To: dropdown */
    lv_obj_t *to_lbl = lv_label_create(body);
    lv_label_set_text(to_lbl, "To:");
    lv_obj_set_style_text_color(to_lbl, lv_color_hex(0xBBBBBB), 0);
    lv_obj_set_pos(to_lbl, 0, 0);

    contact_dd = lv_dropdown_create(body);
    lv_obj_set_size(contact_dd, DEVICE_HOR_RES - 40, 28);
    lv_obj_set_pos(contact_dd, 24, 0);
    lv_obj_set_style_text_font(contact_dd, &lv_font_montserrat_12, 0);

    /* Message text area */
    lv_obj_t *msg_lbl = lv_label_create(body);
    lv_label_set_text(msg_lbl, "Message:");
    lv_obj_set_style_text_color(msg_lbl, lv_color_hex(0xBBBBBB), 0);
    lv_obj_set_pos(msg_lbl, 0, 34);

    msg_ta = lv_textarea_create(body);
    lv_obj_set_size(msg_ta, DEVICE_HOR_RES - 16, 100);
    lv_obj_set_pos(msg_ta, 0, 50);
    lv_textarea_set_placeholder_text(msg_ta, "Type your message...");
    lv_obj_add_event_cb(msg_ta, ta_changed_cb, LV_EVENT_VALUE_CHANGED, NULL);
    if (g_app.dev_group) lv_group_add_obj(g_app.dev_group, msg_ta);

    /* Char count */
    char_count_lbl = lv_label_create(body);
    lv_label_set_text(char_count_lbl, "0/1023");
    lv_obj_set_style_text_color(char_count_lbl, lv_color_hex(0x666666), 0);
    lv_obj_set_style_text_font(char_count_lbl, &lv_font_montserrat_10, 0);
    lv_obj_set_pos(char_count_lbl, DEVICE_HOR_RES - 70, 154);

    /* Send button */
    send_btn = lv_button_create(body);
    lv_obj_set_size(send_btn, DEVICE_HOR_RES - 16, 30);
    lv_obj_set_pos(send_btn, 0, 168);
    lv_obj_set_style_bg_color(send_btn, lv_color_hex(0x00C853), 0);
    lv_obj_add_event_cb(send_btn, send_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *send_lbl = lv_label_create(send_btn);
    lv_label_set_text(send_lbl, LV_SYMBOL_OK " Send Encrypted");
    lv_obj_set_style_text_color(send_lbl, lv_color_white(), 0);
    lv_obj_center(send_lbl);

    /* Status line */
    status_lbl = lv_label_create(body);
    lv_label_set_text(status_lbl, "");
    lv_obj_set_style_text_font(status_lbl, &lv_font_montserrat_10, 0);
    lv_obj_set_pos(status_lbl, 0, 200);
    lv_obj_set_width(status_lbl, DEVICE_HOR_RES - 16);
    lv_label_set_long_mode(status_lbl, LV_LABEL_LONG_WRAP);
}

void scr_compose_refresh(void)
{
    /* Populate dropdown with established contacts only */
    char options[1024] = "";
    dd_count = 0;

    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (g_app.contacts[i].status == CONTACT_ESTABLISHED) {
            if (dd_count > 0) strcat(options, "\n");
            strncat(options, g_app.contacts[i].name, sizeof(options) - strlen(options) - 2);
            dd_to_contact[dd_count] = i;
            dd_count++;
        }
    }

    if (dd_count == 0) {
        lv_dropdown_set_options(contact_dd, "(no established contacts)");
    } else {
        lv_dropdown_set_options(contact_dd, options);
    }

    /* Pre-select if we have a selected contact */
    if (g_app.selected_contact_id) {
        for (uint32_t i = 0; i < dd_count; i++) {
            if (g_app.contacts[dd_to_contact[i]].id == g_app.selected_contact_id) {
                lv_dropdown_set_selected(contact_dd, i);
                break;
            }
        }
    }

    lv_label_set_text(status_lbl, "");
}
