import androidx.compose.runtime.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.osmapp.data.FileStorage
import com.osmapp.data.MessageStore
import com.osmapp.model.*
import com.osmapp.transport.TcpTransport
import com.osmapp.ui.CompanionAppUI
import kotlinx.coroutines.*

fun main(args: Array<String>) {
    var portFilter: Int? = null
    var windowTitle = "Companion App"
    var storeDir: String? = null
    var i = 0
    while (i < args.size) {
        when (args[i]) {
            "--port" -> { i++; portFilter = args.getOrNull(i)?.toIntOrNull() }
            "--title" -> { i++; args.getOrNull(i)?.let { windowTitle = "CA — $it" } }
            "--data-dir" -> { i++; storeDir = args.getOrNull(i) }
        }
        i++
    }

    val storage = FileStorage(storeDir ?: (System.getProperty("user.home") + "/.osm-ca"))
    val store = MessageStore(storage)

    application {
    val transport = remember { TcpTransport(portFilter) }
    val scope = rememberCoroutineScope()
    var devices by remember { mutableStateOf(listOf<OsmDevice>()) }

    /* Helper: persist inbox/outbox for a device after state change */
    fun persistDevice(deviceId: String) {
        val dev = devices.find { it.id == deviceId } ?: return
        store.saveInbox(deviceId, dev.inbox)
        store.saveOutbox(deviceId, dev.outbox)
    }

    // Set up transport callbacks
    LaunchedEffect(Unit) {
        transport.onDeviceDiscovered { discovered ->
            val existing = devices.find { it.id == discovered.id }
            if (existing == null) {
                // Load persisted messages for this device
                val inbox = store.loadInbox(discovered.id)
                val outbox = store.loadOutbox(discovered.id)
                devices = devices + discovered.copy(inbox = inbox, outbox = outbox)
                // Auto-connect to newly discovered devices
                if (discovered.state == ConnectionState.DISCONNECTED) {
                    scope.launch {
                        devices = devices.map {
                            if (it.id == discovered.id) it.copy(state = ConnectionState.CONNECTING) else it
                        }
                        val ok = transport.connect(discovered)
                        if (!ok) {
                            devices = devices.map {
                                if (it.id == discovered.id) it.copy(state = ConnectionState.DISCONNECTED) else it
                            }
                        }
                    }
                }
            } else {
                // Update state but keep inbox/outbox
                devices = devices.map {
                    if (it.id == discovered.id) it.copy(
                        state = if (it.state == ConnectionState.CONNECTED) it.state else discovered.state
                    ) else it
                }
            }
        }

        transport.onMessage { deviceId, data ->
            val text = String(data, Charsets.UTF_8)
            println("[CA] Received from $deviceId: ${text.take(60)}...")
            val msgId = TcpTransport.computeMsgId(data).joinToString("") { "%02x".format(it) }
            devices = devices.map {
                if (it.id == deviceId) it.copy(
                    inbox = it.inbox + CipherMessage(text, direction = CipherMessage.Direction.FROM_OSM, msgId = msgId)
                ) else it
            }
            persistDevice(deviceId)
        }

        transport.onAck { deviceId, msgIdBytes ->
            val hex = msgIdBytes.joinToString("") { "%02x".format(it) }
            println("[CA] ACK from $deviceId: $hex")
            devices = devices.map {
                if (it.id == deviceId) it.copy(
                    outbox = it.outbox.map { msg ->
                        if (msg.msgId == hex) msg.copy(delivered = true) else msg
                    }
                ) else it
            }
            persistDevice(deviceId)
        }

        transport.onConnectionChange { deviceId, connected ->
            devices = devices.map {
                if (it.id == deviceId) it.copy(
                    state = if (connected) ConnectionState.CONNECTED else ConnectionState.DISCONNECTED
                ) else it
            }
            if (connected) {
                // Flush undelivered outbox messages on reconnect
                val dev = devices.find { it.id == deviceId }
                dev?.outbox?.filter { !it.delivered }?.forEach { msg ->
                    val data = msg.text.toByteArray(Charsets.UTF_8)
                    scope.launch { transport.send(deviceId, data) }
                }
            }
        }

        transport.startDiscovery()
    }

    DisposableEffect(Unit) {
        onDispose {
            transport.stopDiscovery()
            // Persist all devices before exit
            devices.forEach {
                store.saveInbox(it.id, it.inbox)
                store.saveOutbox(it.id, it.outbox)
                transport.disconnect(it.id)
            }
        }
    }

    Window(
        onCloseRequest = ::exitApplication,
        title = windowTitle,
        state = rememberWindowState(width = 700.dp, height = 500.dp)
    ) {
        CompanionAppUI(
            devices = devices,
            onConnect = { device ->
                devices = devices.map {
                    if (it.id == device.id) it.copy(state = ConnectionState.CONNECTING) else it
                }
                scope.launch {
                    val ok = transport.connect(device)
                    if (!ok) {
                        devices = devices.map {
                            if (it.id == device.id) it.copy(state = ConnectionState.DISCONNECTED) else it
                        }
                    }
                }
            },
            onDisconnect = { deviceId ->
                transport.disconnect(deviceId)
            },
            onSendText = { deviceId, text ->
                val data = text.toByteArray(Charsets.UTF_8)
                val msgId = TcpTransport.computeMsgId(data).joinToString("") { "%02x".format(it) }
                val msg = CipherMessage(text, direction = CipherMessage.Direction.TO_OSM, msgId = msgId)
                devices = devices.map {
                    if (it.id == deviceId) it.copy(
                        outbox = it.outbox + msg
                    ) else it
                }
                persistDevice(deviceId)
                val dev = devices.find { it.id == deviceId }
                if (dev?.state == ConnectionState.CONNECTED) {
                    scope.launch {
                        transport.send(deviceId, data)
                    }
                }
            }
        )
    }
    }
}
