#ifndef SCR_KEY_EXCHANGE_H
#define SCR_KEY_EXCHANGE_H

#include "../app.h"

void scr_key_exchange_create(void);
void scr_key_exchange_refresh(void);

/* Widget accessors for UI-driven testing */
lv_obj_t *scr_key_exchange_get_action_btn(void);

#endif
