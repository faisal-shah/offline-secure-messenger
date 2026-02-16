#include "contacts.h"
#include "../hal/hal_storage_util.h"
#include "../hal/hal_log.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define CONTACTS_FILE "data_contacts.json"

void contacts_load(void)
{
    size_t len = 0;
    char *buf = hal_storage_read_file(CONTACTS_FILE, &len);
    if (!buf) return;

    /* Simple JSON-ish parser — one contact per line block */
    g_app.contact_count = 0;
    g_app.next_contact_id = 1;

    const char *p = buf;
    while (g_app.contact_count < MAX_CONTACTS) {
        const char *id_str = strstr(p, "\"id\":");
        if (!id_str) break;

        contact_t *c = &g_app.contacts[g_app.contact_count];
        memset(c, 0, sizeof(*c));

        sscanf(id_str, "\"id\":%u", &c->id);

        const char *name_str = strstr(id_str, "\"name\":\"");
        if (name_str) {
            name_str += 8;
            const char *end = strchr(name_str, '"');
            if (end) {
                size_t nlen = end - name_str;
                if (nlen >= MAX_NAME_LEN) nlen = MAX_NAME_LEN - 1;
                memcpy(c->name, name_str, nlen);
            }
        }

        const char *status_str = strstr(id_str, "\"status\":");
        if (status_str) sscanf(status_str, "\"status\":%d", (int *)&c->status);

        const char *unread_str = strstr(id_str, "\"unread\":");
        if (unread_str) sscanf(unread_str, "\"unread\":%u", &c->unread_count);

        const char *pk_str = strstr(id_str, "\"pubkey\":\"");
        if (pk_str) {
            pk_str += 10;
            const char *end = strchr(pk_str, '"');
            if (end) {
                size_t klen = end - pk_str;
                if (klen >= MAX_KEY_LEN) klen = MAX_KEY_LEN - 1;
                memcpy(c->public_key, pk_str, klen);
            }
        }

        if (c->id >= g_app.next_contact_id)
            g_app.next_contact_id = c->id + 1;

        g_app.contact_count++;

        p = id_str + 5;
    }

    free(buf);

    if (g_app.contact_count == 0 && len > 2)
        hal_log("Contacts", "WARNING: file has data but 0 contacts parsed");
}

void contacts_save(void)
{
    char buf[8192];
    int pos = 0;

    pos += snprintf(buf + pos, sizeof(buf) - pos, "[\n");
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        contact_t *c = &g_app.contacts[i];
        pos += snprintf(buf + pos, sizeof(buf) - pos,
                "  {\"id\":%u, \"name\":\"%s\", \"status\":%d, \"unread\":%u, "
                "\"pubkey\":\"%s\"}%s\n",
                c->id, c->name, c->status, c->unread_count,
                c->public_key,
                (i < g_app.contact_count - 1) ? "," : "");
    }
    pos += snprintf(buf + pos, sizeof(buf) - pos, "]\n");
    int err = hal_storage_write_file(CONTACTS_FILE, buf, (size_t)pos);
    if (err) {
        g_app.storage_error = true;
        if (err == LFS_ERR_NOSPC) g_app.storage_full = true;
    }
}

contact_t *contacts_add(const char *name)
{
    if (g_app.contact_count >= MAX_CONTACTS) return NULL;

    contact_t *c = &g_app.contacts[g_app.contact_count];
    memset(c, 0, sizeof(*c));
    c->id = g_app.next_contact_id++;
    strncpy(c->name, name, MAX_NAME_LEN - 1);
    c->status = CONTACT_PENDING_SENT;
    c->created_at = time(NULL);
    g_app.contact_count++;
    return c;
}

bool contacts_delete(uint32_t id)
{
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (g_app.contacts[i].id == id) {
            /* Shift remaining contacts down */
            for (uint32_t j = i; j < g_app.contact_count - 1; j++) {
                g_app.contacts[j] = g_app.contacts[j + 1];
            }
            g_app.contact_count--;
            memset(&g_app.contacts[g_app.contact_count], 0, sizeof(contact_t));
            return true;
        }
    }
    return false;
}

contact_t *contacts_find_by_id(uint32_t id)
{
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (g_app.contacts[i].id == id) return &g_app.contacts[i];
    }
    return NULL;
}

contact_t *contacts_find_by_name(const char *name)
{
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (strcmp(g_app.contacts[i].name, name) == 0) return &g_app.contacts[i];
    }
    return NULL;
}

uint32_t contacts_count_by_status(contact_status_t status)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_app.contact_count; i++) {
        if (g_app.contacts[i].status == status) count++;
    }
    return count;
}
