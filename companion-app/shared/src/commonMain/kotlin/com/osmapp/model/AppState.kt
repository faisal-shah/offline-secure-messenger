package com.osmapp.model

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/** A single message received from or to be sent to an OSM device. */
data class CipherMessage(
    val text: String,
    val timestamp: Long = System.currentTimeMillis(),
    val direction: Direction = Direction.FROM_OSM,
    val msgId: String = "",      /* hex-encoded first 8 bytes of SHA-512 */
    val delivered: Boolean = false  /* true when ACK received (TO_OSM only) */
) {
    enum class Direction { FROM_OSM, TO_OSM }
}

/** Connection state of an OSM device. */
enum class ConnectionState { DISCONNECTED, CONNECTING, CONNECTED }

/** Represents a discovered/connected OSM device. */
data class OsmDevice(
    val id: String,
    val name: String,
    val port: Int,
    val state: ConnectionState = ConnectionState.DISCONNECTED,
    val inbox: List<CipherMessage> = emptyList(),
    val outbox: List<CipherMessage> = emptyList()
)

/** App-wide state. */
class AppState {
    private val _devices = MutableStateFlow<List<OsmDevice>>(emptyList())
    val devices: StateFlow<List<OsmDevice>> = _devices

    fun updateDevices(devices: List<OsmDevice>) {
        _devices.value = devices
    }

    fun updateDevice(id: String, transform: (OsmDevice) -> OsmDevice) {
        _devices.value = _devices.value.map { if (it.id == id) transform(it) else it }
    }

    fun addDevice(device: OsmDevice) {
        _devices.value = _devices.value + device
    }
}
