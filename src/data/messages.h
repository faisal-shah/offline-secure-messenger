#ifndef MESSAGES_H
#define MESSAGES_H

#include "../app.h"

void       messages_load(void);
void       messages_save(void);
message_t *messages_add(uint32_t contact_id, msg_direction_t dir, const char *plaintext);
uint32_t   messages_count_for_contact(uint32_t contact_id);
message_t *messages_get_latest_for_contact(uint32_t contact_id);

#endif
