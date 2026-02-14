#include "messages.h"
#include "../crypto_sim.h"
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
    FILE *f = fopen(MESSAGES_FILE, "r");
    if (!f) return;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (len <= 0) { fclose(f); return; }

    char *buf = malloc(len + 1);
    fread(buf, 1, len, f);
    buf[len] = '\0';
    fclose(f);

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
    FILE *f = fopen(MESSAGES_FILE, "w");
    if (!f) return;

    fprintf(f, "[\n");
    for (uint32_t i = 0; i < g_app.message_count; i++) {
        message_t *m = &g_app.messages[i];
        char escaped[MAX_TEXT_LEN * 2];
        json_escape(escaped, m->plaintext, sizeof(escaped));
        fprintf(f, "  {\"id\":%u, \"cid\":%u, \"dir\":%d, \"ts\":%ld, \"text\":\"%s\"}%s\n",
                m->id, m->contact_id, m->direction, m->timestamp, escaped,
                (i < g_app.message_count - 1) ? "," : "");
    }
    fprintf(f, "]\n");
    fclose(f);
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
    crypto_sim_encrypt(plaintext, contact_id, m->ciphertext, MAX_CIPHER_LEN);
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
