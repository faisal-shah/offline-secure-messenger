/**
 * I/O Monitor — Second SDL window for observing device output
 * and injecting simulated incoming data.
 *
 * Top: scrollable output log (text blocks leaving the device)
 * Bottom: simulation controls (DH replies, incoming messages, new contacts)
 */
#include "io_monitor.h"
#include "app.h"
#include "data/contacts.h"
#include "data/messages.h"
#include "crypto_sim.h"
#include "screens/scr_home.h"
#include "screens/scr_contacts.h"
#include "screens/scr_inbox.h"
#include "screens/scr_key_exchange.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static lv_display_t *mon_disp;

/* Output log widgets */
static lv_obj_t *log_cont;

/* Simulation controls widgets */
static lv_obj_t *sim_cont;
static lv_obj_t *pending_list;      /* container for pending DH buttons */
static lv_obj_t *msg_contact_dd;    /* dropdown for established contacts */
static lv_obj_t *msg_text_ta;       /* textarea for incoming message text */
static lv_obj_t *no_pending_lbl;
static lv_obj_t *no_established_lbl;

/* Map dropdown index → contact array index (established only) */
static uint32_t est_map[MAX_CONTACTS];
static uint32_t est_count;

/* Map pending button index → contact array index */
static uint32_t pend_map[MAX_CONTACTS];
static uint32_t pend_count;

/* Random names for "new person contacts you" */
static const char *random_names[] = {
    "Charlie", "Diana", "Eve", "Frank", "Grace",
    "Hank", "Iris", "Jack", "Kim", "Leo"
};
#define NUM_RANDOM_NAMES 10
static int name_idx = 0;

/*---------- Output Log ----------*/

void io_monitor_log(const char *context, const char *data)
{
    if (!log_cont) return;

    /* Timestamp */
    time_t now = time(NULL);
    struct tm *tm = localtime(&now);
    char ts[16];
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    /* Build log line */
    char line[512];
    snprintf(line, sizeof(line), "[%s] %s\n%.60s%s",
             ts, context, data, strlen(data) > 60 ? "..." : "");

    /* Save default display, switch to monitor */
    lv_display_t *prev = lv_display_get_default();
    lv_display_set_default(mon_disp);

    lv_obj_t *entry = lv_label_create(log_cont);
    lv_label_set_text(entry, line);
    lv_obj_set_width(entry, IO_MON_HOR_RES - 24);
    lv_label_set_long_mode(entry, LV_LABEL_LONG_WRAP);
    lv_obj_set_style_text_color(entry, lv_color_hex(0x00E676), 0);
    lv_obj_set_style_text_font(entry, &lv_font_montserrat_10, 0);
    lv_obj_set_style_bg_color(entry, lv_color_hex(0x0D1117), 0);
    lv_obj_set_style_bg_opa(entry, LV_OPA_COVER, 0);
    lv_obj_set_style_pad_all(entry, 3, 0);
    lv_obj_set_style_radius(entry, 3, 0);

    /* Scroll to bottom */
    lv_obj_scroll_to_y(log_cont, LV_COORD_MAX, LV_ANIM_OFF);

    lv_display_set_default(prev);
}

/*---------- Simulation Callbacks ----------*/

static void sim_dh_reply_cb(lv_event_t *e)
{
    uint32_t idx = (uint32_t)(uintptr_t)lv_event_get_user_data(e);
    if (idx >= g_app.contact_count) return;

    contact_t *c = &g_app.contacts[idx];
    if (c->status != CONTACT_PENDING_SENT) return;

    /* Simulate receiving their DH public key */
    crypto_sim_generate_dh_pubkey(c->public_key, MAX_KEY_LEN);
    snprintf(c->shared_secret, MAX_KEY_LEN, "simulated_shared_%u", c->id);
    c->status = CONTACT_ESTABLISHED;
    contacts_save();

    char buf[128];
    snprintf(buf, sizeof(buf), "DH Reply from %s (exchange complete)", c->name);
    io_monitor_log("INCOMING DH", buf);

    /* Refresh all affected screens */
    io_monitor_refresh();
    scr_home_refresh();
    scr_contacts_refresh();
    if (g_app.selected_contact_id == c->id)
        scr_key_exchange_refresh();
}

static void sim_incoming_msg_cb(lv_event_t *e)
{
    (void)e;
    uint32_t sel = lv_dropdown_get_selected(msg_contact_dd);
    if (sel >= est_count) return;

    const char *text = lv_textarea_get_text(msg_text_ta);
    if (!text || strlen(text) == 0) return;

    uint32_t ci = est_map[sel];
    contact_t *c = &g_app.contacts[ci];

    message_t *msg = messages_add(c->id, MSG_RECEIVED, text);
    if (msg) {
        c->unread_count++;
        messages_save();
        contacts_save();

        char buf[256];
        snprintf(buf, sizeof(buf), "From %s: \"%.*s\"", c->name, 80, text);
        io_monitor_log("INCOMING MSG", buf);

        lv_display_t *prev = lv_display_get_default();
        lv_display_set_default(mon_disp);
        lv_textarea_set_text(msg_text_ta, "");
        lv_display_set_default(prev);

        scr_home_refresh();
        scr_inbox_refresh();
    }
}

static void sim_new_contact_cb(lv_event_t *e)
{
    (void)e;
    const char *name = random_names[name_idx % NUM_RANDOM_NAMES];
    name_idx++;

    /* Check if name already exists, append number if so */
    char final_name[MAX_NAME_LEN];
    if (contacts_find_by_name(name)) {
        snprintf(final_name, sizeof(final_name), "%s_%d", name, name_idx);
    } else {
        snprintf(final_name, sizeof(final_name), "%s", name);
    }

    contact_t *c = contacts_add(final_name);
    if (c) {
        c->status = CONTACT_PENDING_RECEIVED;
        crypto_sim_generate_dh_pubkey(c->public_key, MAX_KEY_LEN);
        contacts_save();

        char buf[128];
        snprintf(buf, sizeof(buf), "%s wants to establish secure channel", final_name);
        io_monitor_log("NEW CONTACT", buf);

        io_monitor_refresh();
        scr_home_refresh();
        scr_contacts_refresh();
    }
}

/*---------- Create / Refresh ----------*/

void io_monitor_create(lv_display_t *disp)
{
    mon_disp = disp;

    lv_display_t *prev = lv_display_get_default();
    lv_display_set_default(disp);

    lv_obj_t *scr = lv_screen_active();
    lv_obj_set_style_bg_color(scr, lv_color_hex(0x0D1117), 0);

    /* ===== Title bar ===== */
    lv_obj_t *title_bar = lv_obj_create(scr);
    lv_obj_set_size(title_bar, IO_MON_HOR_RES, 24);
    lv_obj_set_pos(title_bar, 0, 0);
    lv_obj_set_style_bg_color(title_bar, lv_color_hex(0x161B22), 0);
    lv_obj_set_style_border_width(title_bar, 0, 0);
    lv_obj_set_style_radius(title_bar, 0, 0);
    lv_obj_set_style_pad_all(title_bar, 3, 0);
    lv_obj_set_scrollbar_mode(title_bar, LV_SCROLLBAR_MODE_OFF);

    lv_obj_t *title = lv_label_create(title_bar);
    lv_label_set_text(title, LV_SYMBOL_EYE_OPEN " I/O Monitor — Device Output & Simulation");
    lv_obj_set_style_text_color(title, lv_color_hex(0x58A6FF), 0);
    lv_obj_set_style_text_font(title, &lv_font_montserrat_12, 0);
    lv_obj_align(title, LV_ALIGN_LEFT_MID, 0, 0);

    /* ===== Output Log Section (top half) ===== */
    lv_obj_t *log_header = lv_label_create(scr);
    lv_label_set_text(log_header, "OUTPUT LOG (text blocks leaving device)");
    lv_obj_set_style_text_color(log_header, lv_color_hex(0x8B949E), 0);
    lv_obj_set_style_text_font(log_header, &lv_font_montserrat_10, 0);
    lv_obj_set_pos(log_header, 8, 28);

    log_cont = lv_obj_create(scr);
    lv_obj_set_size(log_cont, IO_MON_HOR_RES - 8, 150);
    lv_obj_set_pos(log_cont, 4, 42);
    lv_obj_set_style_bg_color(log_cont, lv_color_hex(0x0D1117), 0);
    lv_obj_set_style_border_color(log_cont, lv_color_hex(0x30363D), 0);
    lv_obj_set_style_border_width(log_cont, 1, 0);
    lv_obj_set_style_radius(log_cont, 4, 0);
    lv_obj_set_style_pad_all(log_cont, 4, 0);
    lv_obj_set_layout(log_cont, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(log_cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(log_cont, 3, 0);

    /* Initial empty message */
    lv_obj_t *empty = lv_label_create(log_cont);
    lv_label_set_text(empty, "(no output yet — send a message or start a key exchange)");
    lv_obj_set_style_text_color(empty, lv_color_hex(0x484F58), 0);
    lv_obj_set_style_text_font(empty, &lv_font_montserrat_10, 0);

    /* ===== Simulation Controls Section (bottom half) ===== */
    lv_obj_t *sim_header = lv_label_create(scr);
    lv_label_set_text(sim_header, "SIMULATION CONTROLS");
    lv_obj_set_style_text_color(sim_header, lv_color_hex(0x8B949E), 0);
    lv_obj_set_style_text_font(sim_header, &lv_font_montserrat_10, 0);
    lv_obj_set_pos(sim_header, 8, 198);

    sim_cont = lv_obj_create(scr);
    lv_obj_set_size(sim_cont, IO_MON_HOR_RES - 8, 188);
    lv_obj_set_pos(sim_cont, 4, 212);
    lv_obj_set_style_bg_color(sim_cont, lv_color_hex(0x161B22), 0);
    lv_obj_set_style_border_color(sim_cont, lv_color_hex(0x30363D), 0);
    lv_obj_set_style_border_width(sim_cont, 1, 0);
    lv_obj_set_style_radius(sim_cont, 4, 0);
    lv_obj_set_style_pad_all(sim_cont, 6, 0);
    lv_obj_set_layout(sim_cont, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(sim_cont, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(sim_cont, 4, 0);

    /* --- Pending Key Exchanges --- */
    lv_obj_t *pend_hdr = lv_label_create(sim_cont);
    lv_label_set_text(pend_hdr, LV_SYMBOL_REFRESH " Pending Key Exchanges:");
    lv_obj_set_style_text_color(pend_hdr, lv_color_hex(0xFFD600), 0);
    lv_obj_set_style_text_font(pend_hdr, &lv_font_montserrat_10, 0);

    pending_list = lv_obj_create(sim_cont);
    lv_obj_set_size(pending_list, IO_MON_HOR_RES - 28, 40);
    lv_obj_set_style_bg_opa(pending_list, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(pending_list, 0, 0);
    lv_obj_set_style_pad_all(pending_list, 0, 0);
    lv_obj_set_layout(pending_list, LV_LAYOUT_FLEX);
    lv_obj_set_flex_flow(pending_list, LV_FLEX_FLOW_ROW);
    lv_obj_set_style_pad_column(pending_list, 4, 0);
    lv_obj_set_scrollbar_mode(pending_list, LV_SCROLLBAR_MODE_OFF);

    no_pending_lbl = lv_label_create(pending_list);
    lv_label_set_text(no_pending_lbl, "(none pending)");
    lv_obj_set_style_text_color(no_pending_lbl, lv_color_hex(0x484F58), 0);
    lv_obj_set_style_text_font(no_pending_lbl, &lv_font_montserrat_10, 0);

    /* --- Separator --- */
    lv_obj_t *sep1 = lv_obj_create(sim_cont);
    lv_obj_set_size(sep1, IO_MON_HOR_RES - 28, 1);
    lv_obj_set_style_bg_color(sep1, lv_color_hex(0x30363D), 0);
    lv_obj_set_style_border_width(sep1, 0, 0);

    /* --- Simulate Incoming Message --- */
    lv_obj_t *msg_hdr = lv_label_create(sim_cont);
    lv_label_set_text(msg_hdr, LV_SYMBOL_ENVELOPE " Simulate Incoming Message:");
    lv_obj_set_style_text_color(msg_hdr, lv_color_hex(0x00B0FF), 0);
    lv_obj_set_style_text_font(msg_hdr, &lv_font_montserrat_10, 0);

    /* Row: From: [dropdown] */
    lv_obj_t *from_row = lv_obj_create(sim_cont);
    lv_obj_set_size(from_row, IO_MON_HOR_RES - 28, 28);
    lv_obj_set_style_bg_opa(from_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(from_row, 0, 0);
    lv_obj_set_style_pad_all(from_row, 0, 0);
    lv_obj_set_scrollbar_mode(from_row, LV_SCROLLBAR_MODE_OFF);

    lv_obj_t *from_lbl = lv_label_create(from_row);
    lv_label_set_text(from_lbl, "From:");
    lv_obj_set_style_text_color(from_lbl, lv_color_hex(0xBBBBBB), 0);
    lv_obj_set_style_text_font(from_lbl, &lv_font_montserrat_10, 0);
    lv_obj_align(from_lbl, LV_ALIGN_LEFT_MID, 0, 0);

    msg_contact_dd = lv_dropdown_create(from_row);
    lv_obj_set_size(msg_contact_dd, 200, 26);
    lv_obj_align(msg_contact_dd, LV_ALIGN_LEFT_MID, 40, 0);
    lv_obj_set_style_text_font(msg_contact_dd, &lv_font_montserrat_10, 0);

    no_established_lbl = lv_label_create(from_row);
    lv_label_set_text(no_established_lbl, "(no established contacts)");
    lv_obj_set_style_text_color(no_established_lbl, lv_color_hex(0x484F58), 0);
    lv_obj_set_style_text_font(no_established_lbl, &lv_font_montserrat_10, 0);
    lv_obj_align(no_established_lbl, LV_ALIGN_LEFT_MID, 40, 0);

    /* Row: Message text + Send button */
    lv_obj_t *msg_row = lv_obj_create(sim_cont);
    lv_obj_set_size(msg_row, IO_MON_HOR_RES - 28, 28);
    lv_obj_set_style_bg_opa(msg_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(msg_row, 0, 0);
    lv_obj_set_style_pad_all(msg_row, 0, 0);
    lv_obj_set_scrollbar_mode(msg_row, LV_SCROLLBAR_MODE_OFF);

    msg_text_ta = lv_textarea_create(msg_row);
    lv_obj_set_size(msg_text_ta, 310, 26);
    lv_obj_align(msg_text_ta, LV_ALIGN_LEFT_MID, 0, 0);
    lv_textarea_set_one_line(msg_text_ta, true);
    lv_textarea_set_placeholder_text(msg_text_ta, "Type simulated message...");
    lv_obj_set_style_text_font(msg_text_ta, &lv_font_montserrat_10, 0);

    lv_obj_t *send_btn = lv_button_create(msg_row);
    lv_obj_set_size(send_btn, 140, 26);
    lv_obj_align(send_btn, LV_ALIGN_RIGHT_MID, 0, 0);
    lv_obj_set_style_bg_color(send_btn, lv_color_hex(0x238636), 0);
    lv_obj_add_event_cb(send_btn, sim_incoming_msg_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *send_lbl = lv_label_create(send_btn);
    lv_label_set_text(send_lbl, LV_SYMBOL_DOWNLOAD " Inject Message");
    lv_obj_set_style_text_color(send_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(send_lbl, &lv_font_montserrat_10, 0);
    lv_obj_center(send_lbl);

    /* --- Separator --- */
    lv_obj_t *sep2 = lv_obj_create(sim_cont);
    lv_obj_set_size(sep2, IO_MON_HOR_RES - 28, 1);
    lv_obj_set_style_bg_color(sep2, lv_color_hex(0x30363D), 0);
    lv_obj_set_style_border_width(sep2, 0, 0);

    /* --- New Inbound Contact --- */
    lv_obj_t *new_btn = lv_button_create(sim_cont);
    lv_obj_set_size(new_btn, IO_MON_HOR_RES - 28, 28);
    lv_obj_set_style_bg_color(new_btn, lv_color_hex(0x6E40C9), 0);
    lv_obj_add_event_cb(new_btn, sim_new_contact_cb, LV_EVENT_CLICKED, NULL);
    lv_obj_t *new_lbl = lv_label_create(new_btn);
    lv_label_set_text(new_lbl, LV_SYMBOL_PLUS " Simulate: New Person Contacts You");
    lv_obj_set_style_text_color(new_lbl, lv_color_white(), 0);
    lv_obj_set_style_text_font(new_lbl, &lv_font_montserrat_10, 0);
    lv_obj_center(new_lbl);

    lv_display_set_default(prev);
}

void io_monitor_refresh(void)
{
    if (!mon_disp) return;

    lv_display_t *prev = lv_display_get_default();
    lv_display_set_default(mon_disp);

    /* --- Refresh pending DH list --- */
    lv_obj_clean(pending_list);
    pend_count = 0;

    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (g_app.contacts[i].status == CONTACT_PENDING_SENT) {
            pend_map[pend_count] = i;
            pend_count++;

            lv_obj_t *btn = lv_button_create(pending_list);
            lv_obj_set_height(btn, 28);
            lv_obj_set_style_bg_color(btn, lv_color_hex(0xFFD600), 0);
            lv_obj_set_style_pad_hor(btn, 8, 0);
            lv_obj_add_event_cb(btn, sim_dh_reply_cb, LV_EVENT_CLICKED,
                                (void *)(uintptr_t)i);

            lv_obj_t *lbl = lv_label_create(btn);
            char text[64];
            snprintf(text, sizeof(text), LV_SYMBOL_OK " %s replies", g_app.contacts[i].name);
            lv_label_set_text(lbl, text);
            lv_obj_set_style_text_color(lbl, lv_color_hex(0x0D1117), 0);
            lv_obj_set_style_text_font(lbl, &lv_font_montserrat_10, 0);
            lv_obj_center(lbl);
        }
    }

    if (pend_count == 0) {
        no_pending_lbl = lv_label_create(pending_list);
        lv_label_set_text(no_pending_lbl, "(none pending)");
        lv_obj_set_style_text_color(no_pending_lbl, lv_color_hex(0x484F58), 0);
        lv_obj_set_style_text_font(no_pending_lbl, &lv_font_montserrat_10, 0);
    }

    /* --- Refresh established contacts dropdown --- */
    char options[1024] = "";
    est_count = 0;

    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (g_app.contacts[i].status == CONTACT_ESTABLISHED) {
            if (est_count > 0) strcat(options, "\n");
            strncat(options, g_app.contacts[i].name,
                    sizeof(options) - strlen(options) - 2);
            est_map[est_count] = i;
            est_count++;
        }
    }

    if (est_count > 0) {
        lv_dropdown_set_options(msg_contact_dd, options);
        lv_obj_clear_flag(msg_contact_dd, LV_OBJ_FLAG_HIDDEN);
        lv_obj_add_flag(no_established_lbl, LV_OBJ_FLAG_HIDDEN);
    } else {
        lv_dropdown_set_options(msg_contact_dd, "");
        lv_obj_add_flag(msg_contact_dd, LV_OBJ_FLAG_HIDDEN);
        lv_obj_clear_flag(no_established_lbl, LV_OBJ_FLAG_HIDDEN);
    }

    lv_display_set_default(prev);
}
