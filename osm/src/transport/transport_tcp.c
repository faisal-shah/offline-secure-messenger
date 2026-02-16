/**
 * TCP transport implementation for desktop simulator.
 * OSM listens on a TCP port; CA(s) connect as clients.
 *
 * TCP framing: [4 bytes msg_len][2 bytes char_uuid][packet_data]
 * Fragmentation: [1 byte flags][2 bytes seq][payload]
 */
#include "transport.h"
#include "../hal/hal_log.h"
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
#include <sys/uio.h>

/* TCP frame header */
#pragma pack(push, 1)
typedef struct {
    uint32_t msg_len;    /* total bytes after this header */
    uint16_t char_uuid;  /* characteristic UUID */
} tcp_frame_header_t;
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
        hal_log("Transport", "socket() failed");
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
        hal_log("Transport", "bind() failed");
        close(t->server_fd);
        t->server_fd = -1;
        return false;
    }

    if (listen(t->server_fd, TRANSPORT_MAX_CLIENTS) < 0) {
        hal_log("Transport", "listen() failed");
        close(t->server_fd);
        t->server_fd = -1;
        return false;
    }

    t->running = true;
    {
        char msg[48];
        snprintf(msg, sizeof(msg), "Listening on port %d", t->port);
        hal_log("Transport", msg);
    }
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
        hal_log("Transport", "Rejected connection (no slots)");
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

    {
        char msg[32];
        snprintf(msg, sizeof(msg), "Client %d connected", slot);
        hal_log("Transport", msg);
    }
    if (t->callbacks.on_connect)
        t->callbacks.on_connect(slot);
}

/* Read TCP frames from a client (handles partial frames across reads) */
static void read_client(transport_t *t, int idx)
{
    transport_client_t *c = &t->clients[idx];

    /* Append new data to the per-client TCP buffer */
    size_t space = sizeof(c->tcp_buf) - c->tcp_buf_len;
    if (space == 0) {
        c->tcp_buf_len = 0;
        return;
    }

    ssize_t n = recv(c->fd, c->tcp_buf + c->tcp_buf_len, space, 0);
    if (n <= 0) {
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK)) {
            close(c->fd);
            c->fd = -1;
            c->state = CLIENT_DISCONNECTED;
            c->rx_active = false;
            c->rx_len = 0;
            c->tcp_buf_len = 0;
            {
                char msg[32];
                snprintf(msg, sizeof(msg), "Client %d disconnected", idx);
                hal_log("Transport", msg);
            }
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
            break;

        pos += sizeof(tcp_frame_header_t);
        transport_process_fragment(t, idx, hdr.char_uuid,
                                   c->tcp_buf + pos, hdr.msg_len);
        pos += hdr.msg_len;
    }

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

/* TCP transport only provides init, start, stop, poll, and send_raw.
 * All other transport_* functions (send_message, broadcast, connected_count,
 * set_callbacks, compute_msg_id, send_ack, process_fragment) are in
 * transport_common.c shared by all backends. */
