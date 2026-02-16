/**
 * Common transport logic shared between TCP and BLE backends.
 * - Fragment processing / reassembly
 * - Fragment sending (fragmentation)
 * - ACK computation / sending
 * - Broadcast, connected count, callback management
 */
#include "transport.h"
#include "../tweetnacl.h"
#include <stdio.h>
#include <string.h>

/* Fragment header (packed, matches wire format) */
#pragma pack(push, 1)
typedef struct {
    uint8_t  flags;
    uint16_t seq;
} frag_header_t;
#pragma pack(pop)

void transport_process_fragment(transport_t *t, int client_idx,
                                uint16_t char_uuid,
                                const uint8_t *frag_data, size_t frag_len)
{
    if (frag_len < sizeof(frag_header_t)) return;

    transport_client_t *c = &t->clients[client_idx];
    const frag_header_t *fh = (const frag_header_t *)frag_data;
    const uint8_t *payload = frag_data + sizeof(frag_header_t);
    size_t payload_len = frag_len - sizeof(frag_header_t);

    /* Handle incoming ACK */
    if (fh->flags & FRAG_FLAG_ACK) {
        if (payload_len >= TRANSPORT_ACK_ID_LEN && t->callbacks.on_ack)
            t->callbacks.on_ack(client_idx, payload);
        return;
    }

    if (fh->flags & FRAG_FLAG_START) {
        c->rx_len = 0;
        c->rx_expected_seq = 0;
        c->rx_active = true;

        if (payload_len < 2) return;
        uint16_t total_len = payload[0] | ((uint16_t)payload[1] << 8);
        if (total_len > TRANSPORT_MAX_MSG_SIZE) {
            c->rx_active = false;
            return;
        }
        payload += 2;
        payload_len -= 2;
    }

    if (!c->rx_active) return;
    if (fh->seq != c->rx_expected_seq) {
        c->rx_active = false;
        c->rx_len = 0;
        return;
    }

    if (c->rx_len + payload_len > TRANSPORT_MAX_MSG_SIZE) {
        c->rx_active = false;
        c->rx_len = 0;
        return;
    }
    memcpy(c->rx_buf + c->rx_len, payload, payload_len);
    c->rx_len += payload_len;
    c->rx_expected_seq++;

    if (fh->flags & FRAG_FLAG_END) {
        uint8_t ack_id[TRANSPORT_ACK_ID_LEN];
        transport_compute_msg_id(c->rx_buf, c->rx_len, ack_id);
        transport_send_ack(t, client_idx, ack_id);

        if (t->callbacks.on_message)
            t->callbacks.on_message(client_idx, char_uuid,
                                    c->rx_buf, c->rx_len);
        c->rx_active = false;
        c->rx_len = 0;
    }
}

bool transport_send_message(transport_t *t, int client_idx,
                            uint16_t char_uuid,
                            const uint8_t *data, size_t len)
{
    size_t max_payload = TRANSPORT_MTU - 3; /* 3 = sizeof(frag_header_t) */
    uint16_t seq = 0;
    size_t offset = 0;

    while (offset < len) {
        size_t chunk = len - offset;
        bool is_start = (offset == 0);
        bool is_end = false;

        size_t overhead = is_start ? 2 : 0;
        if (chunk + overhead > max_payload)
            chunk = max_payload - overhead;
        if (offset + chunk >= len)
            is_end = true;

        uint8_t frag[TRANSPORT_MTU];
        frag[0] = 0;
        if (is_start) frag[0] |= FRAG_FLAG_START;
        if (is_end)   frag[0] |= FRAG_FLAG_END;
        frag[1] = (uint8_t)(seq & 0xFF);
        frag[2] = (uint8_t)((seq >> 8) & 0xFF);

        size_t frag_len = 3;

        if (is_start) {
            frag[frag_len++] = (uint8_t)(len & 0xFF);
            frag[frag_len++] = (uint8_t)((len >> 8) & 0xFF);
        }

        memcpy(frag + frag_len, data + offset, chunk);
        frag_len += chunk;

        if (!transport_send_raw(t, client_idx, char_uuid, frag, frag_len))
            return false;

        offset += chunk;
        seq++;
    }
    return true;
}

void transport_broadcast_message(transport_t *t, uint16_t char_uuid,
                                 const uint8_t *data, size_t len)
{
    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        if (t->clients[i].state == CLIENT_CONNECTED)
            transport_send_message(t, i, char_uuid, data, len);
    }
}

int transport_connected_count(const transport_t *t)
{
    int count = 0;
    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        if (t->clients[i].state == CLIENT_CONNECTED) count++;
    }
    return count;
}

void transport_set_callbacks(transport_t *t, transport_callbacks_t cbs)
{
    t->callbacks = cbs;
}

void transport_compute_msg_id(const uint8_t *data, size_t len,
                              uint8_t out[TRANSPORT_ACK_ID_LEN])
{
    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512(hash, data, len);
    memcpy(out, hash, TRANSPORT_ACK_ID_LEN);
}

bool transport_send_ack(transport_t *t, int client_idx,
                        const uint8_t msg_id[TRANSPORT_ACK_ID_LEN])
{
    uint8_t frag[3 + TRANSPORT_ACK_ID_LEN];
    frag[0] = FRAG_FLAG_ACK;
    frag[1] = 0;
    frag[2] = 0;
    memcpy(frag + 3, msg_id, TRANSPORT_ACK_ID_LEN);
    return transport_send_raw(t, client_idx, CHAR_UUID_TX, frag, sizeof(frag));
}
