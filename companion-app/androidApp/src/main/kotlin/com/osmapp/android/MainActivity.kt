package com.osmapp.android

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.*
import androidx.core.content.ContextCompat
import com.osmapp.data.FileStorage
import com.osmapp.data.MessageStore
import com.osmapp.model.*
import com.osmapp.transport.BleTransport
import com.osmapp.ui.CompanionAppUI
import kotlinx.coroutines.*

class MainActivity : ComponentActivity() {

    private lateinit var transport: BleTransport
    private lateinit var store: MessageStore

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { grants ->
        if (grants.values.all { it }) {
            transport.startDiscovery()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val storage = FileStorage(filesDir.absolutePath)
        store = MessageStore(storage)
        transport = BleTransport(this)

        setContent {
            val scope = rememberCoroutineScope()
            var devices by remember { mutableStateOf(listOf<OsmDevice>()) }

            fun persistDevice(deviceId: String) {
                val dev = devices.find { it.id == deviceId } ?: return
                store.saveInbox(deviceId, dev.inbox)
                store.saveOutbox(deviceId, dev.outbox)
            }

            LaunchedEffect(Unit) {
                transport.onDeviceDiscovered { discovered ->
                    val existing = devices.find { it.id == discovered.id }
                    if (existing == null) {
                        val inbox = store.loadInbox(discovered.id)
                        val outbox = store.loadOutbox(discovered.id)
                        devices = devices + discovered.copy(inbox = inbox, outbox = outbox)
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
                    }
                }

                transport.onMessage { deviceId, data ->
                    val text = String(data, Charsets.UTF_8)
                    val msgId = BleTransport.computeMsgId(data).joinToString("") { "%02x".format(it) }
                    devices = devices.map {
                        if (it.id == deviceId) it.copy(
                            inbox = it.inbox + CipherMessage(text, direction = CipherMessage.Direction.FROM_OSM, msgId = msgId)
                        ) else it
                    }
                    persistDevice(deviceId)
                }

                transport.onAck { deviceId, msgIdBytes ->
                    val hex = msgIdBytes.joinToString("") { "%02x".format(it) }
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
                        val dev = devices.find { it.id == deviceId }
                        dev?.outbox?.filter { !it.delivered }?.forEach { msg ->
                            val d = msg.text.toByteArray(Charsets.UTF_8)
                            scope.launch { transport.send(deviceId, d) }
                        }
                    }
                }

                requestBlePermissions()
            }

            DisposableEffect(Unit) {
                onDispose {
                    transport.stopDiscovery()
                    devices.forEach {
                        store.saveInbox(it.id, it.inbox)
                        store.saveOutbox(it.id, it.outbox)
                        transport.disconnect(it.id)
                    }
                }
            }

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
                    val msgId = BleTransport.computeMsgId(data).joinToString("") { "%02x".format(it) }
                    val msg = CipherMessage(text, direction = CipherMessage.Direction.TO_OSM, msgId = msgId)
                    devices = devices.map {
                        if (it.id == deviceId) it.copy(outbox = it.outbox + msg) else it
                    }
                    persistDevice(deviceId)
                    val dev = devices.find { it.id == deviceId }
                    if (dev?.state == ConnectionState.CONNECTED) {
                        scope.launch { transport.send(deviceId, data) }
                    }
                }
            )
        }
    }

    private fun requestBlePermissions() {
        val needed = mutableListOf<String>()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN)
                != PackageManager.PERMISSION_GRANTED) needed.add(Manifest.permission.BLUETOOTH_SCAN)
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT)
                != PackageManager.PERMISSION_GRANTED) needed.add(Manifest.permission.BLUETOOTH_CONNECT)
        }
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
            != PackageManager.PERMISSION_GRANTED) needed.add(Manifest.permission.ACCESS_FINE_LOCATION)

        if (needed.isEmpty()) {
            transport.startDiscovery()
        } else {
            permissionLauncher.launch(needed.toTypedArray())
        }
    }
}
