import androidx.compose.runtime.*
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Window
import androidx.compose.ui.window.application
import androidx.compose.ui.window.rememberWindowState
import com.osmapp.model.*
import com.osmapp.transport.TcpTransport
import com.osmapp.ui.CompanionAppUI
import kotlinx.coroutines.*

fun main() = application {
    val transport = remember { TcpTransport() }
    val scope = rememberCoroutineScope()
    var devices by remember { mutableStateOf(listOf<OsmDevice>()) }

    // Set up transport callbacks
    LaunchedEffect(Unit) {
        transport.onDeviceDiscovered { discovered ->
            val existing = devices.find { it.id == discovered.id }
            if (existing == null) {
                devices = devices + discovered
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
            devices = devices.map {
                if (it.id == deviceId) it.copy(
                    inbox = it.inbox + CipherMessage(text, direction = CipherMessage.Direction.FROM_OSM)
                ) else it
            }
        }

        transport.onConnectionChange { deviceId, connected ->
            devices = devices.map {
                if (it.id == deviceId) it.copy(
                    state = if (connected) ConnectionState.CONNECTED else ConnectionState.DISCONNECTED
                ) else it
            }
        }

        transport.startDiscovery()
    }

    DisposableEffect(Unit) {
        onDispose {
            transport.stopDiscovery()
            devices.forEach { transport.disconnect(it.id) }
        }
    }

    Window(
        onCloseRequest = ::exitApplication,
        title = "Companion App",
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
                val msg = CipherMessage(text, direction = CipherMessage.Direction.TO_OSM)
                devices = devices.map {
                    if (it.id == deviceId) it.copy(
                        outbox = it.outbox + msg
                    ) else it
                }
                scope.launch {
                    transport.send(deviceId, text.toByteArray(Charsets.UTF_8))
                }
            }
        )
    }
}
