#ifndef TRANSPORT_H
#define TRANSPORT_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

/**
 * Transport layer — abstract interface for sending/receiving data
 * between the OSM and Companion App(s).
 *
 * Desktop simulator: TCP (OSM listens, CA connects)
 * Hardware: BLE GATT
 */

#define TRANSPORT_MAX_CLIENTS  4
#define TRANSPORT_MTU          200   /* BLE-realistic MTU for payload */
#define TRANSPORT_MAX_MSG_SIZE 4096  /* Max reassembled message */
#define TRANSPORT_DEFAULT_PORT 19200

/* Fragmentation flags */
#define FRAG_FLAG_START  0x01
#define FRAG_FLAG_END    0x02
#define FRAG_FLAG_ACK    0x04

/* BLE GATT characteristic UUIDs (as 16-bit short IDs) */
#define CHAR_UUID_TX      0xFE02  /* OSM → CA (Notify) */
#define CHAR_UUID_RX      0xFE03  /* CA → OSM (Write) */
#define CHAR_UUID_STATUS  0xFE04
#define CHAR_UUID_INFO    0xFE05

/* Client connection state */
typedef enum {
    CLIENT_DISCONNECTED = 0,
    CLIENT_CONNECTED,
} client_state_t;

typedef struct {
    int             fd;
    client_state_t  state;
    char            name[32];

    /* Reassembly buffer for incoming fragments */
    uint8_t         rx_buf[TRANSPORT_MAX_MSG_SIZE];
    size_t          rx_len;
    uint16_t        rx_expected_seq;
    bool            rx_active;

    /* TCP stream buffer for partial frame handling */
    uint8_t         tcp_buf[TRANSPORT_MAX_MSG_SIZE];
    size_t          tcp_buf_len;
} transport_client_t;

/* Callbacks */
typedef void (*transport_on_connect_cb)(int client_idx);
typedef void (*transport_on_disconnect_cb)(int client_idx);
typedef void (*transport_on_message_cb)(int client_idx, uint16_t char_uuid,
                                       const uint8_t *data, size_t len);

typedef struct {
    transport_on_connect_cb    on_connect;
    transport_on_disconnect_cb on_disconnect;
    transport_on_message_cb    on_message;
} transport_callbacks_t;

typedef struct {
    int                 server_fd;
    uint16_t            port;
    bool                running;
    transport_client_t  clients[TRANSPORT_MAX_CLIENTS];
    transport_callbacks_t callbacks;
} transport_t;

/* Initialize transport (does not start listening) */
void transport_init(transport_t *t, uint16_t port);

/* Start listening for connections */
bool transport_start(transport_t *t);

/* Stop transport and close all connections */
void transport_stop(transport_t *t);

/* Poll for new connections and incoming data (non-blocking) */
void transport_poll(transport_t *t);

/* Send raw data to a client on a specific characteristic */
bool transport_send_raw(transport_t *t, int client_idx,
                        uint16_t char_uuid,
                        const uint8_t *data, size_t len);

/* Send a message with fragmentation */
bool transport_send_message(transport_t *t, int client_idx,
                            uint16_t char_uuid,
                            const uint8_t *data, size_t len);

/* Send a message to all connected clients */
void transport_broadcast_message(transport_t *t, uint16_t char_uuid,
                                 const uint8_t *data, size_t len);

/* Get number of connected clients */
int transport_connected_count(const transport_t *t);

/* Set callbacks */
void transport_set_callbacks(transport_t *t, transport_callbacks_t cbs);

#endif /* TRANSPORT_H */
