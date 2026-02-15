/**
 * BLE transport — BlueZ GATT server via D-Bus (libdbus-1).
 *
 * Registers a custom GATT service with:
 *   TX (0xFE02) — Notify (OSM → CA)
 *   RX (0xFE03) — Write Without Response (CA → OSM)
 *   INFO (0xFE05) — Read (device name)
 *
 * Implements LE advertising so the OSM appears as a BLE peripheral.
 * The CA (Android) connects as a central/GATT client.
 *
 * Common functions (send_message, broadcast, connected_count, etc.)
 * are provided by transport_common.c.
 */
#include "transport.h"
#include <dbus/dbus.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TAG "[transport-ble]"

/* 128-bit UUIDs based on Bluetooth SIG base + 0xFE00 */
#define SERVICE_UUID   "0000fe00-0000-1000-8000-00805f9b34fb"
#define TX_CHAR_UUID   "0000fe02-0000-1000-8000-00805f9b34fb"
#define RX_CHAR_UUID   "0000fe03-0000-1000-8000-00805f9b34fb"
#define INFO_CHAR_UUID "0000fe05-0000-1000-8000-00805f9b34fb"

/* D-Bus object paths */
#define APP_PATH       "/com/osmapp/ble"
#define SVC_PATH       "/com/osmapp/ble/service0"
#define TX_PATH        "/com/osmapp/ble/service0/tx"
#define RX_PATH        "/com/osmapp/ble/service0/rx"
#define INFO_PATH      "/com/osmapp/ble/service0/info"
#define ADV_PATH       "/com/osmapp/ble/advertisement0"

/* BlueZ well-known name and adapter path */
#define BLUEZ_BUS_NAME "org.bluez"
#define ADAPTER_PATH   "/org/bluez/hci0"

/* D-Bus interface names */
#define OBJECT_MANAGER_IFACE  "org.freedesktop.DBus.ObjectManager"
#define PROPERTIES_IFACE      "org.freedesktop.DBus.Properties"
#define GATT_MANAGER_IFACE    "org.bluez.GattManager1"
#define GATT_SERVICE_IFACE    "org.bluez.GattService1"
#define GATT_CHAR_IFACE       "org.bluez.GattCharacteristic1"
#define LE_ADV_MANAGER_IFACE  "org.bluez.LEAdvertisingManager1"
#define LE_ADV_IFACE          "org.bluez.LEAdvertisement1"

/* BLE state stored alongside transport_t */
static DBusConnection *g_dbus = NULL;
static bool g_app_registered = false;
static bool g_adv_registered = false;
static bool g_notifying = false;
static char g_device_name[64] = "OSM Device";

/* Forward declarations */
static DBusHandlerResult handle_message(DBusConnection *conn, DBusMessage *msg, void *data);

/*===========================================================================
 * D-Bus helper — append a variant containing a string
 *=========================================================================*/
static void append_variant_string(DBusMessageIter *iter, const char *value)
{
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "s", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_STRING, &value);
    dbus_message_iter_close_container(iter, &variant);
}

static void append_variant_bool(DBusMessageIter *iter, dbus_bool_t value)
{
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "b", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_BOOLEAN, &value);
    dbus_message_iter_close_container(iter, &variant);
}

static void append_variant_object_path(DBusMessageIter *iter, const char *path)
{
    DBusMessageIter variant;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "o", &variant);
    dbus_message_iter_append_basic(&variant, DBUS_TYPE_OBJECT_PATH, &path);
    dbus_message_iter_close_container(iter, &variant);
}

static void append_variant_string_array(DBusMessageIter *iter,
                                        const char **strings, int count)
{
    DBusMessageIter variant, array;
    dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT, "as", &variant);
    dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "s", &array);
    for (int i = 0; i < count; i++)
        dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &strings[i]);
    dbus_message_iter_close_container(&variant, &array);
    dbus_message_iter_close_container(iter, &variant);
}

/*===========================================================================
 * Add a dict entry {string: variant} to an open dict/array iterator
 *=========================================================================*/
static void dict_append_entry_string(DBusMessageIter *dict, const char *key, const char *val)
{
    DBusMessageIter entry;
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
    append_variant_string(&entry, val);
    dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_entry_bool(DBusMessageIter *dict, const char *key, dbus_bool_t val)
{
    DBusMessageIter entry;
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
    append_variant_bool(&entry, val);
    dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_entry_object_path(DBusMessageIter *dict, const char *key, const char *path)
{
    DBusMessageIter entry;
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
    append_variant_object_path(&entry, path);
    dbus_message_iter_close_container(dict, &entry);
}

static void dict_append_entry_string_array(DBusMessageIter *dict, const char *key,
                                           const char **strings, int count)
{
    DBusMessageIter entry;
    dbus_message_iter_open_container(dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
    append_variant_string_array(&entry, strings, count);
    dbus_message_iter_close_container(dict, &entry);
}

/*===========================================================================
 * Build the properties for each GATT object
 *=========================================================================*/

/* Append one interface's properties as {string: {string: variant}} */
static void append_char_properties(DBusMessageIter *iface_dict,
                                   const char *iface,
                                   const char *uuid,
                                   const char *service_path,
                                   const char **flags, int nflags)
{
    DBusMessageIter entry, props;
    dbus_message_iter_open_container(iface_dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &iface);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sv}", &props);
    dict_append_entry_string(&props, "UUID", uuid);
    dict_append_entry_object_path(&props, "Service", service_path);
    dict_append_entry_string_array(&props, "Flags", flags, nflags);
    dbus_message_iter_close_container(&entry, &props);
    dbus_message_iter_close_container(iface_dict, &entry);
}

static void append_service_properties(DBusMessageIter *iface_dict)
{
    DBusMessageIter entry, props;
    const char *iface = GATT_SERVICE_IFACE;
    dbus_message_iter_open_container(iface_dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &iface);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_ARRAY, "{sv}", &props);
    dict_append_entry_string(&props, "UUID", SERVICE_UUID);
    dict_append_entry_bool(&props, "Primary", TRUE);
    dbus_message_iter_close_container(&entry, &props);
    dbus_message_iter_close_container(iface_dict, &entry);
}

/*===========================================================================
 * ObjectManager.GetManagedObjects — returns the entire GATT object tree
 *=========================================================================*/
static DBusMessage *build_managed_objects(DBusMessage *request)
{
    DBusMessage *reply = dbus_message_new_method_return(request);
    DBusMessageIter iter, array;
    dbus_message_iter_init_append(reply, &iter);
    /* a{oa{sa{sv}}} */
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{oa{sa{sv}}}", &array);

    /* Service object */
    {
        DBusMessageIter obj_entry, iface_dict;
        const char *path = SVC_PATH;
        dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &obj_entry);
        dbus_message_iter_append_basic(&obj_entry, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_open_container(&obj_entry, DBUS_TYPE_ARRAY, "{sa{sv}}", &iface_dict);
        append_service_properties(&iface_dict);
        dbus_message_iter_close_container(&obj_entry, &iface_dict);
        dbus_message_iter_close_container(&array, &obj_entry);
    }

    /* TX characteristic (Notify) */
    {
        DBusMessageIter obj_entry, iface_dict;
        const char *path = TX_PATH;
        const char *flags[] = {"notify"};
        dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &obj_entry);
        dbus_message_iter_append_basic(&obj_entry, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_open_container(&obj_entry, DBUS_TYPE_ARRAY, "{sa{sv}}", &iface_dict);
        append_char_properties(&iface_dict, GATT_CHAR_IFACE, TX_CHAR_UUID, SVC_PATH, flags, 1);
        dbus_message_iter_close_container(&obj_entry, &iface_dict);
        dbus_message_iter_close_container(&array, &obj_entry);
    }

    /* RX characteristic (Write Without Response) */
    {
        DBusMessageIter obj_entry, iface_dict;
        const char *path = RX_PATH;
        const char *flags[] = {"write-without-response"};
        dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &obj_entry);
        dbus_message_iter_append_basic(&obj_entry, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_open_container(&obj_entry, DBUS_TYPE_ARRAY, "{sa{sv}}", &iface_dict);
        append_char_properties(&iface_dict, GATT_CHAR_IFACE, RX_CHAR_UUID, SVC_PATH, flags, 1);
        dbus_message_iter_close_container(&obj_entry, &iface_dict);
        dbus_message_iter_close_container(&array, &obj_entry);
    }

    /* INFO characteristic (Read) */
    {
        DBusMessageIter obj_entry, iface_dict;
        const char *path = INFO_PATH;
        const char *flags[] = {"read"};
        dbus_message_iter_open_container(&array, DBUS_TYPE_DICT_ENTRY, NULL, &obj_entry);
        dbus_message_iter_append_basic(&obj_entry, DBUS_TYPE_OBJECT_PATH, &path);
        dbus_message_iter_open_container(&obj_entry, DBUS_TYPE_ARRAY, "{sa{sv}}", &iface_dict);
        append_char_properties(&iface_dict, GATT_CHAR_IFACE, INFO_CHAR_UUID, SVC_PATH, flags, 1);
        dbus_message_iter_close_container(&obj_entry, &iface_dict);
        dbus_message_iter_close_container(&array, &obj_entry);
    }

    dbus_message_iter_close_container(&iter, &array);
    return reply;
}

/*===========================================================================
 * Advertisement GetManagedObjects for LEAdvertisement1
 *=========================================================================*/
static DBusMessage *build_adv_properties(DBusMessage *request)
{
    DBusMessage *reply = dbus_message_new_method_return(request);
    DBusMessageIter iter, dict;
    dbus_message_iter_init_append(reply, &iter);
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);

    dict_append_entry_string(&dict, "Type", "peripheral");
    dict_append_entry_string(&dict, "LocalName", g_device_name);

    /* ServiceUUIDs */
    {
        const char *uuids[] = {SERVICE_UUID};
        dict_append_entry_string_array(&dict, "ServiceUUIDs", uuids, 1);
    }

    dbus_message_iter_close_container(&iter, &dict);
    return reply;
}

/*===========================================================================
 * D-Bus message handler — dispatches method calls to our objects
 *=========================================================================*/
static transport_t *g_transport = NULL;  /* set during init */

static DBusHandlerResult handle_message(DBusConnection *conn, DBusMessage *msg, void *data)
{
    (void)data;
    const char *path = dbus_message_get_path(msg);
    const char *member = dbus_message_get_member(msg);

    if (!path || !member) return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;

    /* ObjectManager.GetManagedObjects on the app root */
    if (dbus_message_is_method_call(msg, OBJECT_MANAGER_IFACE, "GetManagedObjects")
        && strcmp(path, APP_PATH) == 0) {
        DBusMessage *reply = build_managed_objects(msg);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* RX WriteValue — data from CA */
    if (dbus_message_is_method_call(msg, GATT_CHAR_IFACE, "WriteValue")
        && strcmp(path, RX_PATH) == 0) {
        DBusMessageIter iter;
        if (dbus_message_iter_init(msg, &iter) &&
            dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {
            DBusMessageIter arr;
            dbus_message_iter_recurse(&iter, &arr);
            int n = dbus_message_iter_get_element_count(&iter);
            if (n > 0) {
                uint8_t *buf;
                int count;
                dbus_message_iter_get_fixed_array(&arr, &buf, &count);
                if (count > 0 && g_transport) {
                    transport_process_fragment(g_transport, 0, CHAR_UUID_RX, buf, (size_t)count);
                }
            }
        }
        DBusMessage *reply = dbus_message_new_method_return(msg);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* INFO ReadValue — return device name */
    if (dbus_message_is_method_call(msg, GATT_CHAR_IFACE, "ReadValue")
        && strcmp(path, INFO_PATH) == 0) {
        DBusMessage *reply = dbus_message_new_method_return(msg);
        DBusMessageIter iter, arr;
        dbus_message_iter_init_append(reply, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "y", &arr);
        size_t nlen = strlen(g_device_name);
        for (size_t i = 0; i < nlen; i++) {
            uint8_t b = (uint8_t)g_device_name[i];
            dbus_message_iter_append_basic(&arr, DBUS_TYPE_BYTE, &b);
        }
        dbus_message_iter_close_container(&iter, &arr);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* TX StartNotify / StopNotify */
    if (dbus_message_is_method_call(msg, GATT_CHAR_IFACE, "StartNotify")
        && strcmp(path, TX_PATH) == 0) {
        g_notifying = true;
        fprintf(stderr, "%s StartNotify — client subscribed\n", TAG);
        /* Treat as client connect */
        if (g_transport) {
            g_transport->clients[0].state = CLIENT_CONNECTED;
            snprintf(g_transport->clients[0].name, 32, "BLE-0");
            if (g_transport->callbacks.on_connect)
                g_transport->callbacks.on_connect(0);
        }
        DBusMessage *reply = dbus_message_new_method_return(msg);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }
    if (dbus_message_is_method_call(msg, GATT_CHAR_IFACE, "StopNotify")
        && strcmp(path, TX_PATH) == 0) {
        g_notifying = false;
        fprintf(stderr, "%s StopNotify — client unsubscribed\n", TAG);
        if (g_transport) {
            g_transport->clients[0].state = CLIENT_DISCONNECTED;
            if (g_transport->callbacks.on_disconnect)
                g_transport->callbacks.on_disconnect(0);
        }
        DBusMessage *reply = dbus_message_new_method_return(msg);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* LEAdvertisement1.Release */
    if (dbus_message_is_method_call(msg, LE_ADV_IFACE, "Release")
        && strcmp(path, ADV_PATH) == 0) {
        fprintf(stderr, "%s Advertisement released\n", TAG);
        g_adv_registered = false;
        DBusMessage *reply = dbus_message_new_method_return(msg);
        dbus_connection_send(conn, reply, NULL);
        dbus_message_unref(reply);
        return DBUS_HANDLER_RESULT_HANDLED;
    }

    /* Properties.GetAll — BlueZ queries object properties this way */
    if (dbus_message_is_method_call(msg, PROPERTIES_IFACE, "GetAll")) {
        if (strcmp(path, ADV_PATH) == 0) {
            DBusMessage *reply = build_adv_properties(msg);
            dbus_connection_send(conn, reply, NULL);
            dbus_message_unref(reply);
            return DBUS_HANDLER_RESULT_HANDLED;
        }
    }

    return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

/* D-Bus object path vtable */
static DBusObjectPathVTable vtable = {
    .unregister_function = NULL,
    .message_function = handle_message,
};

/*===========================================================================
 * transport_init — connect to D-Bus
 *=========================================================================*/
void transport_init(transport_t *t, uint16_t port)
{
    (void)port;
    memset(t, 0, sizeof(*t));
    g_transport = t;
    g_notifying = false;
    g_app_registered = false;
    g_adv_registered = false;

    /* Set device name from port (for identification in multi-instance setups) */
    snprintf(g_device_name, sizeof(g_device_name), "OSM-%u", (unsigned)port);
    fprintf(stderr, "%s init (device name: %s)\n", TAG, g_device_name);
}

/*===========================================================================
 * transport_start — register GATT app + advertisement with BlueZ
 *=========================================================================*/
bool transport_start(transport_t *t)
{
    DBusError err;
    dbus_error_init(&err);

    g_dbus = dbus_bus_get(DBUS_BUS_SYSTEM, &err);
    if (!g_dbus || dbus_error_is_set(&err)) {
        fprintf(stderr, "%s Failed to connect to system D-Bus: %s\n", TAG,
                err.message ? err.message : "unknown");
        dbus_error_free(&err);
        return false;
    }

    /* Register our object paths */
    const char *paths[] = {APP_PATH, SVC_PATH, TX_PATH, RX_PATH, INFO_PATH, ADV_PATH};
    for (int i = 0; i < 6; i++) {
        if (!dbus_connection_register_object_path(g_dbus, paths[i], &vtable, t)) {
            fprintf(stderr, "%s Failed to register path %s\n", TAG, paths[i]);
            return false;
        }
    }

    /* Register GATT application with BlueZ */
    {
        DBusMessage *call = dbus_message_new_method_call(
            BLUEZ_BUS_NAME, ADAPTER_PATH, GATT_MANAGER_IFACE, "RegisterApplication");
        const char *app_path = APP_PATH;
        dbus_message_append_args(call,
            DBUS_TYPE_OBJECT_PATH, &app_path,
            DBUS_TYPE_INVALID);
        /* Append empty options dict: a{sv} */
        DBusMessageIter iter, dict;
        dbus_message_iter_init_append(call, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
        dbus_message_iter_close_container(&iter, &dict);

        DBusMessage *reply = dbus_connection_send_with_reply_and_block(g_dbus, call, 5000, &err);
        dbus_message_unref(call);
        if (!reply || dbus_error_is_set(&err)) {
            fprintf(stderr, "%s RegisterApplication failed: %s\n", TAG,
                    err.message ? err.message : "unknown");
            dbus_error_free(&err);
            /* Non-fatal — keep running for D-Bus testing */
        } else {
            g_app_registered = true;
            fprintf(stderr, "%s GATT application registered\n", TAG);
            dbus_message_unref(reply);
        }
    }

    /* Register LE advertisement */
    {
        DBusMessage *call = dbus_message_new_method_call(
            BLUEZ_BUS_NAME, ADAPTER_PATH, LE_ADV_MANAGER_IFACE, "RegisterAdvertisement");
        const char *adv_path = ADV_PATH;
        dbus_message_append_args(call,
            DBUS_TYPE_OBJECT_PATH, &adv_path,
            DBUS_TYPE_INVALID);
        DBusMessageIter iter, dict;
        dbus_message_iter_init_append(call, &iter);
        dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
        dbus_message_iter_close_container(&iter, &dict);

        DBusMessage *reply = dbus_connection_send_with_reply_and_block(g_dbus, call, 5000, &err);
        dbus_message_unref(call);
        if (!reply || dbus_error_is_set(&err)) {
            fprintf(stderr, "%s RegisterAdvertisement failed: %s\n", TAG,
                    err.message ? err.message : "unknown");
            dbus_error_free(&err);
        } else {
            g_adv_registered = true;
            fprintf(stderr, "%s LE advertisement registered\n", TAG);
            dbus_message_unref(reply);
        }
    }

    t->running = true;
    fprintf(stderr, "%s transport started (GATT=%s, ADV=%s)\n", TAG,
            g_app_registered ? "OK" : "FAIL",
            g_adv_registered ? "OK" : "FAIL");
    return true;
}

/*===========================================================================
 * transport_stop — unregister and disconnect
 *=========================================================================*/
void transport_stop(transport_t *t)
{
    if (g_dbus) {
        if (g_adv_registered) {
            DBusError err;
            dbus_error_init(&err);
            DBusMessage *call = dbus_message_new_method_call(
                BLUEZ_BUS_NAME, ADAPTER_PATH, LE_ADV_MANAGER_IFACE, "UnregisterAdvertisement");
            const char *adv_path = ADV_PATH;
            dbus_message_append_args(call, DBUS_TYPE_OBJECT_PATH, &adv_path, DBUS_TYPE_INVALID);
            DBusMessage *reply = dbus_connection_send_with_reply_and_block(g_dbus, call, 2000, &err);
            dbus_message_unref(call);
            if (reply) dbus_message_unref(reply);
            dbus_error_free(&err);
        }

        if (g_app_registered) {
            DBusError err;
            dbus_error_init(&err);
            DBusMessage *call = dbus_message_new_method_call(
                BLUEZ_BUS_NAME, ADAPTER_PATH, GATT_MANAGER_IFACE, "UnregisterApplication");
            const char *app_path = APP_PATH;
            dbus_message_append_args(call, DBUS_TYPE_OBJECT_PATH, &app_path, DBUS_TYPE_INVALID);
            DBusMessage *reply = dbus_connection_send_with_reply_and_block(g_dbus, call, 2000, &err);
            dbus_message_unref(call);
            if (reply) dbus_message_unref(reply);
            dbus_error_free(&err);
        }

        dbus_connection_unref(g_dbus);
        g_dbus = NULL;
    }

    for (int i = 0; i < TRANSPORT_MAX_CLIENTS; i++) {
        t->clients[i].state = CLIENT_DISCONNECTED;
        t->clients[i].rx_active = false;
        t->clients[i].rx_len = 0;
    }
    t->running = false;
    g_app_registered = false;
    g_adv_registered = false;
    g_notifying = false;
    g_transport = NULL;
    fprintf(stderr, "%s transport stopped\n", TAG);
}

/*===========================================================================
 * transport_poll — process pending D-Bus messages (non-blocking)
 *=========================================================================*/
void transport_poll(transport_t *t)
{
    (void)t;
    if (!g_dbus) return;
    /* Non-blocking: read/write/dispatch with 0 timeout */
    dbus_connection_read_write_dispatch(g_dbus, 0);
}

/*===========================================================================
 * transport_send_raw — send a BLE notification via PropertiesChanged signal
 *=========================================================================*/
bool transport_send_raw(transport_t *t, int client_idx,
                        uint16_t char_uuid,
                        const uint8_t *data, size_t len)
{
    (void)client_idx; (void)char_uuid;
    if (!g_dbus || !g_notifying || !t->running) return false;

    /* Emit PropertiesChanged on the TX characteristic with new Value */
    DBusMessage *sig = dbus_message_new_signal(TX_PATH, PROPERTIES_IFACE, "PropertiesChanged");
    if (!sig) return false;

    DBusMessageIter iter, dict, entry, variant, arr;
    const char *iface = GATT_CHAR_IFACE;
    dbus_message_iter_init_append(sig, &iter);
    dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &iface);

    /* changed_properties: {Value: <byte array>} */
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "{sv}", &dict);
    dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
    const char *key = "Value";
    dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
    dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT, "ay", &variant);
    dbus_message_iter_open_container(&variant, DBUS_TYPE_ARRAY, "y", &arr);
    for (size_t i = 0; i < len; i++) {
        uint8_t b = data[i];
        dbus_message_iter_append_basic(&arr, DBUS_TYPE_BYTE, &b);
    }
    dbus_message_iter_close_container(&variant, &arr);
    dbus_message_iter_close_container(&entry, &variant);
    dbus_message_iter_close_container(&dict, &entry);
    dbus_message_iter_close_container(&iter, &dict);

    /* invalidated_properties: empty array */
    DBusMessageIter inv_arr;
    dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY, "s", &inv_arr);
    dbus_message_iter_close_container(&iter, &inv_arr);

    dbus_connection_send(g_dbus, sig, NULL);
    dbus_message_unref(sig);
    return true;
}
