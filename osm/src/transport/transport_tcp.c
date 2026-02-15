/**
 * TCP transport implementation for desktop simulator.
 * OSM listens on a TCP port; CA(s) connect as clients.
 *
 * TCP framing: [4 bytes msg_len][2 bytes char_uuid][packet_data]
 * Fragmentation: [1 byte flags][2 bytes seq][payload]
 */
#include "transport.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

/* TCP frame header */
#pragma pack(push, 1)
typedef struct {
    uint32_t msg_len;    /* total bytes after this header */
    uint16_t char_uuid;  /* characteristic UUID */
} tcp_frame_header_t;
#pragma pack(pop)

/* Fragment header */
#pragma pack(push, 1)
typedef struct {
    uint8_t  flags;
    uint16_t seq;
} frag_header_t;
#pragma pack(pop)

static void set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

void transport_init(transport_t *t, uint16_t port)
{
    memset(t, 0, sizeof(*t));
    t->server_fd = -1;
    t->port = port;
    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        t->clients[i].fd = -1;
        t->clients[i].state = CLIENT_DISCONNECTED;
    }
}

bool transport_start(transport_t *t)
{
    t->server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (t->server_fd < 0) {
        fprintf(stderr, "[transport] socket() failed: %s\n", strerror(errno));
        return false;
    }

    int opt = 1;
    setsockopt(t->server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    set_nonblocking(t->server_fd);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
        .sin_port = htons(t->port),
    };

    if (bind(t->server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "[transport] bind(%d) failed: %s\n",
                t->port, strerror(errno));
        close(t->server_fd);
        t->server_fd = -1;
        return false;
    }

    if (listen(t->server_fd, TRANSPORT_MAX_CLIENTS) < 0) {
        fprintf(stderr, "[transport] listen() failed: %s\n", strerror(errno));
        close(t->server_fd);
        t->server_fd = -1;
        return false;
    }

    t->running = true;
    fprintf(stderr, "[transport] Listening on port %d\n", t->port);
    return true;
}

void transport_stop(transport_t *t)
{
    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        if (t->clients[i].fd >= 0) {
            close(t->clients[i].fd);
            t->clients[i].fd = -1;
            t->clients[i].state = CLIENT_DISCONNECTED;
        }
    }
    if (t->server_fd >= 0) {
        close(t->server_fd);
        t->server_fd = -1;
    }
    t->running = false;
}

static int find_free_slot(transport_t *t)
{
    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        if (t->clients[i].state == CLIENT_DISCONNECTED)
            return i;
    }
    return -1;
}

static void accept_new_clients(transport_t *t)
{
    struct sockaddr_in caddr;
    socklen_t clen = sizeof(caddr);
    int cfd = accept(t->server_fd, (struct sockaddr *)&caddr, &clen);
    if (cfd < 0) return;

    int slot = find_free_slot(t);
    if (slot < 0) {
        close(cfd);
        fprintf(stderr, "[transport] Rejected connection (no slots)\n");
        return;
    }

    set_nonblocking(cfd);
    int opt = 1;
    setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    transport_client_t *c = &t->clients[slot];
    c->fd = cfd;
    c->state = CLIENT_CONNECTED;
    c->rx_len = 0;
    c->rx_expected_seq = 0;
    c->rx_active = false;
    c->tcp_buf_len = 0;
    snprintf(c->name, sizeof(c->name), "CA-%d", slot);

    fprintf(stderr, "[transport] Client %d connected\n", slot);
    if (t->callbacks.on_connect)
        t->callbacks.on_connect(slot);
}

/* Process a single reassembled fragment payload */
static void process_fragment(transport_t *t, int client_idx,
                             uint16_t char_uuid,
                             const uint8_t *frag_data, size_t frag_len)
{
    if (frag_len < sizeof(frag_header_t)) return;

    transport_client_t *c = &t->clients[client_idx];
    const frag_header_t *fh = (const frag_header_t *)frag_data;
    const uint8_t *payload = frag_data + sizeof(frag_header_t);
    size_t payload_len = frag_len - sizeof(frag_header_t);

    if (fh->flags & FRAG_FLAG_START) {
        c->rx_len = 0;
        c->rx_expected_seq = 0;
        c->rx_active = true;

        /* START packet includes 2-byte total_len before payload */
        if (payload_len < 2) return;
        /* uint16_t total_len = payload[0] | (payload[1] << 8); */
        payload += 2;
        payload_len -= 2;
    }

    if (!c->rx_active) return;
    if (fh->seq != c->rx_expected_seq) {
        /* Sequence mismatch — reset */
        c->rx_active = false;
        c->rx_len = 0;
        return;
    }

    /* Append payload to reassembly buffer */
    if (c->rx_len + payload_len > TRANSPORT_MAX_MSG_SIZE) {
        c->rx_active = false;
        c->rx_len = 0;
        return;
    }
    memcpy(c->rx_buf + c->rx_len, payload, payload_len);
    c->rx_len += payload_len;
    c->rx_expected_seq++;

    if (fh->flags & FRAG_FLAG_END) {
        /* Complete message reassembled */
        if (t->callbacks.on_message)
            t->callbacks.on_message(client_idx, char_uuid,
                                    c->rx_buf, c->rx_len);
        c->rx_active = false;
        c->rx_len = 0;
    }
}

/* Read TCP frames from a client (handles partial frames across reads) */
static void read_client(transport_t *t, int idx)
{
    transport_client_t *c = &t->clients[idx];

    /* Append new data to the per-client TCP buffer */
    size_t space = sizeof(c->tcp_buf) - c->tcp_buf_len;
    if (space == 0) {
        /* Buffer full with no complete frame — reset */
        c->tcp_buf_len = 0;
        return;
    }

    ssize_t n = recv(c->fd, c->tcp_buf + c->tcp_buf_len, space, 0);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            /* Disconnect */
            close(c->fd);
            c->fd = -1;
            c->state = CLIENT_DISCONNECTED;
            c->rx_active = false;
            c->rx_len = 0;
            c->tcp_buf_len = 0;
            fprintf(stderr, "[transport] Client %d disconnected\n", idx);
            if (t->callbacks.on_disconnect)
                t->callbacks.on_disconnect(idx);
        }
        return;
    }

    c->tcp_buf_len += (size_t)n;

    /* Parse complete TCP frames: [4B len][2B uuid][data...] */
    size_t pos = 0;
    while (pos + sizeof(tcp_frame_header_t) <= c->tcp_buf_len) {
        tcp_frame_header_t hdr;
        memcpy(&hdr, c->tcp_buf + pos, sizeof(hdr));
        hdr.msg_len = ntohl(hdr.msg_len);
        hdr.char_uuid = ntohs(hdr.char_uuid);

        if (pos + sizeof(tcp_frame_header_t) + hdr.msg_len > c->tcp_buf_len)
            break;  /* Incomplete frame — wait for more data */

        pos += sizeof(tcp_frame_header_t);
        process_fragment(t, idx, hdr.char_uuid,
                         c->tcp_buf + pos, hdr.msg_len);
        pos += hdr.msg_len;
    }

    /* Shift unconsumed data to front of buffer */
    if (pos > 0) {
        size_t remaining = c->tcp_buf_len - pos;
        if (remaining > 0)
            memmove(c->tcp_buf, c->tcp_buf + pos, remaining);
        c->tcp_buf_len = remaining;
    }
}

void transport_poll(transport_t *t)
{
    if (!t->running) return;

    /* Use select with zero timeout for non-blocking poll */
    fd_set rfds;
    FD_ZERO(&rfds);
    int maxfd = t->server_fd;
    FD_SET(t->server_fd, &rfds);

    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        if (t->clients[i].state == CLIENT_CONNECTED) {
            FD_SET(t->clients[i].fd, &rfds);
            if (t->clients[i].fd > maxfd) maxfd = t->clients[i].fd;
        }
    }

    struct timeval tv = {0, 0};
    int ret = select(maxfd + 1, &rfds, NULL, NULL, &tv);
    if (ret <= 0) return;

    if (FD_ISSET(t->server_fd, &rfds))
        accept_new_clients(t);

    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        if (t->clients[i].state == CLIENT_CONNECTED &&
            FD_ISSET(t->clients[i].fd, &rfds)) {
            read_client(t, i);
        }
    }
}

/* Send a raw TCP frame */
bool transport_send_raw(transport_t *t, int client_idx,
                        uint16_t char_uuid,
                        const uint8_t *data, size_t len)
{
    if (client_idx < 0 || client_idx >= TRANSPORT_MAX_CLIENTS) return false;
    transport_client_t *c = &t->clients[client_idx];
    if (c->state != CLIENT_CONNECTED) return false;

    tcp_frame_header_t hdr = {
        .msg_len = htonl((uint32_t)len),
        .char_uuid = htons(char_uuid),
    };

    /* Send header + data atomically (best-effort for small messages) */
    struct iovec iov[2] = {
        { .iov_base = &hdr, .iov_len = sizeof(hdr) },
        { .iov_base = (void *)data, .iov_len = len },
    };
    struct msghdr msg = { .msg_iov = iov, .msg_iovlen = 2 };
    ssize_t sent = sendmsg(c->fd, &msg, MSG_NOSIGNAL);
    return sent == (ssize_t)(sizeof(hdr) + len);
}

/* Send with fragmentation */
bool transport_send_message(transport_t *t, int client_idx,
                            uint16_t char_uuid,
                            const uint8_t *data, size_t len)
{
    size_t max_payload = TRANSPORT_MTU - sizeof(frag_header_t);
    uint16_t seq = 0;
    size_t offset = 0;

    while (offset < len) {
        size_t chunk = len - offset;
        bool is_start = (offset == 0);
        bool is_end = false;

        /* START packet reserves 2 bytes for total_len */
        size_t overhead = is_start ? 2 : 0;
        if (chunk + overhead > max_payload)
            chunk = max_payload - overhead;
        if (offset + chunk >= len)
            is_end = true;

        /* Build fragment */
        uint8_t frag[TRANSPORT_MTU];
        frag_header_t *fh = (frag_header_t *)frag;
        fh->flags = 0;
        if (is_start) fh->flags |= FRAG_FLAG_START;
        if (is_end)   fh->flags |= FRAG_FLAG_END;
        fh->seq = seq;

        size_t frag_len = sizeof(frag_header_t);

        if (is_start) {
            /* Prepend 2-byte total length */
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
