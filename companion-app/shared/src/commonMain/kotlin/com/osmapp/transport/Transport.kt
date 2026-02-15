package com.osmapp.transport

import com.osmapp.model.OsmDevice

/**
 * Transport interface for discovering and communicating with OSM devices.
 * Desktop: TCP client connecting to OSM's TCP server.
 * Android: BLE GATT client (future).
 */
interface Transport {
    /** Start scanning for available OSM devices. */
    suspend fun startDiscovery()

    /** Stop scanning. */
    fun stopDiscovery()

    /** Connect to a specific OSM device. */
    suspend fun connect(device: OsmDevice): Boolean

    /** Disconnect from a device. */
    fun disconnect(deviceId: String)

    /** Send data to a connected OSM device. */
    suspend fun send(deviceId: String, data: ByteArray): Boolean

    /** Register a listener for incoming data. */
    fun onMessage(listener: (deviceId: String, data: ByteArray) -> Unit)

    /** Register a listener for connection state changes. */
    fun onConnectionChange(listener: (deviceId: String, connected: Boolean) -> Unit)

    /** Register a listener for device discovery. */
    fun onDeviceDiscovered(listener: (OsmDevice) -> Unit)

    /** Register a listener for message delivery ACKs. */
    fun onAck(listener: (deviceId: String, msgId: ByteArray) -> Unit)
}
