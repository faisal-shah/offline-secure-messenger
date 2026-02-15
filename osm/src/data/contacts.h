#ifndef CONTACTS_H
#define CONTACTS_H

#include "../app.h"

void       contacts_load(void);
void       contacts_save(void);
contact_t *contacts_add(const char *name);
bool       contacts_delete(uint32_t id);
contact_t *contacts_find_by_id(uint32_t id);
contact_t *contacts_find_by_name(const char *name);
uint32_t   contacts_count_by_status(contact_status_t status);

#endif
