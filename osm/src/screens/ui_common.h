#ifndef UI_COMMON_H
#define UI_COMMON_H

#include "lvgl.h"

/* Shared status bar — device name, CA indicator, pending-keys badge.
 * Returns the bar container (20px high). Parent should be the screen root. */
lv_obj_t *ui_status_bar_create(lv_obj_t *parent);

/* Update the status bar indicators (CA count, storage, pending keys).
 * Call from each screen's refresh function. */
void ui_status_bar_refresh(lv_obj_t *bar);

/* Bottom tab bar — Contacts | Inbox. active_tab: 0=Contacts, 1=Inbox.
 * Returns the bar container (32px high). */
lv_obj_t *ui_tab_bar_create(lv_obj_t *parent, int active_tab);

/* Update the inbox unread badge on a tab bar. */
void ui_tab_bar_refresh(lv_obj_t *bar);

#endif /* UI_COMMON_H */
