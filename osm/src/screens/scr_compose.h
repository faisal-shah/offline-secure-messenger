#ifndef SCR_COMPOSE_H
#define SCR_COMPOSE_H

#include "../app.h"

void scr_compose_create(void);
void scr_compose_refresh(void);

/* Widget accessors for UI-driven testing */
lv_obj_t *scr_compose_get_msg_ta(void);
lv_obj_t *scr_compose_get_dropdown(void);
lv_obj_t *scr_compose_get_send_btn(void);

#endif
