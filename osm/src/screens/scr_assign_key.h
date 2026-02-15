#ifndef SCR_ASSIGN_KEY_H
#define SCR_ASSIGN_KEY_H

#include "../app.h"

void scr_assign_key_create(void);
void scr_assign_key_refresh(void);

/* Widget accessors for UI-driven testing */
lv_obj_t *scr_assign_key_get_contact_list(void);
lv_obj_t *scr_assign_key_get_new_contact_btn(void);
lv_obj_t *scr_assign_key_get_name_ta(void);
lv_obj_t *scr_assign_key_get_name_ok_btn(void);

#endif
