#ifndef SCR_CONVERSATION_H
#define SCR_CONVERSATION_H

#include "../app.h"

void scr_conversation_create(void);
void scr_conversation_refresh(void);

/* Widget accessors for UI-driven testing */
lv_obj_t *scr_conversation_get_reply_ta(void);
lv_obj_t *scr_conversation_get_send_btn(void);

#endif
