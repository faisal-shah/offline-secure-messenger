#include "messages.h"
#include "../crypto.h"
#include "../data/contacts.h"
#include "../hal/hal_storage_util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MESSAGES_FILE "data_messages.json"

/* Simple JSON escape: just strip quotes from plaintext for safety */
static void json_escape(char *dst, const char *src, size_t max)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j < max - 1; i++) {
        if (src[i] == '"') { if (j + 2 < max) { dst[j++] = '\\'; dst[j++] = '"'; } }
        else if (src[i] == '\\') { if (j + 2 < max) { dst[j++] = '\\'; dst[j++] = '\\'; } }
        else if (src[i] == '\n') { if (j + 2 < max) { dst[j++] = '\\'; dst[j++] = 'n'; } }
        else dst[j++] = src[i];
    }
    dst[j] = '\0';
}

static void json_unescape(char *dst, const char *src, size_t max)
{
    size_t j = 0;
    for (size_t i = 0; src[i] && j < max - 1; i++) {
        if (src[i] == '\\' && src[i+1]) {
            i++;
            if (src[i] == 'n') dst[j++] = '\n';
            else if (src[i] == '"') dst[j++] = '"';
            else if (src[i] == '\\') dst[j++] = '\\';
            else dst[j++] = src[i];
        } else {
            dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

void messages_load(void)
{
    size_t len = 0;
    char *buf = hal_storage_read_file(MESSAGES_FILE, &len);
    if (!buf) return;

    g_app.message_count = 0;
    g_app.next_message_id = 1;

    const char *p = buf;
    while (g_app.message_count < MAX_MESSAGES) {
        const char *id_str = strstr(p, "\"id\":");
        if (!id_str) break;

        message_t *m = &g_app.messages[g_app.message_count];
        memset(m, 0, sizeof(*m));

        sscanf(id_str, "\"id\":%u", &m->id);

        const char *cid_str = strstr(id_str, "\"cid\":");
        if (cid_str) sscanf(cid_str, "\"cid\":%u", &m->contact_id);

        const char *dir_str = strstr(id_str, "\"dir\":");
        if (dir_str) { int d; sscanf(dir_str, "\"dir\":%d", &d); m->direction = d; }

        const char *ts_str = strstr(id_str, "\"ts\":");
        if (ts_str) sscanf(ts_str, "\"ts\":%ld", &m->timestamp);

        const char *txt_str = strstr(id_str, "\"text\":\"");
        if (txt_str) {
            txt_str += 8;
            /* Find closing quote (handle escaped quotes) */
            char raw[MAX_TEXT_LEN];
            size_t j = 0;
            for (size_t i = 0; txt_str[i] && j < MAX_TEXT_LEN - 1; i++) {
                if (txt_str[i] == '\\' && txt_str[i+1]) {
                    raw[j++] = txt_str[i++];
                    if (j < MAX_TEXT_LEN - 1) raw[j++] = txt_str[i];
                } else if (txt_str[i] == '"') {
                    break;
                } else {
                    raw[j++] = txt_str[i];
                }
            }
            raw[j] = '\0';
            json_unescape(m->plaintext, raw, MAX_TEXT_LEN);
        }

        if (m->id >= g_app.next_message_id)
            g_app.next_message_id = m->id + 1;

        g_app.message_count++;
        p = id_str + 5;
    }

    free(buf);
}

void messages_save(void)
{
    /* Messages can be large; use heap buffer */
    size_t buf_size = 256 + g_app.message_count * (MAX_TEXT_LEN * 2 + 128);
    char *buf = malloc(buf_size);
    if (!buf) return;

    int pos = 0;
    pos += snprintf(buf + pos, buf_size - pos, "[\n");
    for (uint32_t i = 0; i < g_app.message_count; i++) {
        message_t *m = &g_app.messages[i];
        char escaped[MAX_TEXT_LEN * 2];
        json_escape(escaped, m->plaintext, sizeof(escaped));
        pos += snprintf(buf + pos, buf_size - pos,
                "  {\"id\":%u, \"cid\":%u, \"dir\":%d, \"ts\":%ld, \"text\":\"%s\"}%s\n",
                m->id, m->contact_id, m->direction, m->timestamp, escaped,
                (i < g_app.message_count - 1) ? "," : "");
    }
    pos += snprintf(buf + pos, buf_size - pos, "]\n");
    if (!hal_storage_write_file(MESSAGES_FILE, buf, (size_t)pos))
        g_app.storage_error = true;
    free(buf);
}

message_t *messages_add(uint32_t contact_id, msg_direction_t dir, const char *plaintext)
{
    if (g_app.message_count >= MAX_MESSAGES) return NULL;

    message_t *m = &g_app.messages[g_app.message_count];
    memset(m, 0, sizeof(*m));
    m->id = g_app.next_message_id++;
    m->contact_id = contact_id;
    m->direction = dir;
    strncpy(m->plaintext, plaintext, MAX_TEXT_LEN - 1);

    /* Encrypt if identity and peer key are available */
    uint8_t peer_pk[CRYPTO_PUBKEY_BYTES];
    contact_t *c = contacts_find_by_id(contact_id);
    if (g_app.identity.valid && c &&
        c->public_key[0] != '\0' &&
        crypto_b64_to_pubkey(c->public_key, peer_pk)) {
        crypto_encrypt(plaintext, peer_pk, g_app.identity.privkey,
                       m->ciphertext, MAX_CIPHER_LEN);
    } else {
        snprintf(m->ciphertext, MAX_CIPHER_LEN, "(unencrypted)");
    }

    m->timestamp = time(NULL);
    g_app.message_count++;
    return m;
}

uint32_t messages_count_for_contact(uint32_t contact_id)
{
    uint32_t count = 0;
    for (uint32_t i = 0; i < g_app.message_count; i++) {
        if (g_app.messages[i].contact_id == contact_id) count++;
    }
    return count;
}

message_t *messages_get_latest_for_contact(uint32_t contact_id)
{
    message_t *latest = NULL;
    for (uint32_t i = 0; i < g_app.message_count; i++) {
        if (g_app.messages[i].contact_id == contact_id) latest = &g_app.messages[i];
    }
    return latest;
}

bool messages_delete_by_id(uint32_t id)
{
    for (uint32_t i = 0; i < g_app.message_count; i++) {
        if (g_app.messages[i].id == id) {
            for (uint32_t j = i; j < g_app.message_count - 1; j++) {
                g_app.messages[j] = g_app.messages[j + 1];
            }
            g_app.message_count--;
            memset(&g_app.messages[g_app.message_count], 0, sizeof(message_t));
            return true;
        }
    }
    return false;
}

void messages_delete_for_contact(uint32_t contact_id)
{
    uint32_t dst = 0;
    for (uint32_t src = 0; src < g_app.message_count; src++) {
        if (g_app.messages[src].contact_id != contact_id) {
            if (dst != src) g_app.messages[dst] = g_app.messages[src];
            dst++;
        }
    }
    /* Clear vacated slots */
    for (uint32_t i = dst; i < g_app.message_count; i++) {
        memset(&g_app.messages[i], 0, sizeof(message_t));
    }
    g_app.message_count = dst;
}
