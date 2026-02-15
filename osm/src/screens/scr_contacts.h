#ifndef SCR_CONTACTS_H
#define SCR_CONTACTS_H

#include "../app.h"

void scr_contacts_create(void);
void scr_contacts_refresh(void);

/* Widget accessors for UI-driven testing */
lv_obj_t *scr_contacts_get_add_btn(void);
lv_obj_t *scr_contacts_get_name_ta(void);
lv_obj_t *scr_contacts_get_name_ok_btn(void);

#endif
