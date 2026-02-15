package com.osmapp.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.osmapp.model.CipherMessage
import com.osmapp.model.ConnectionState
import com.osmapp.model.OsmDevice

val DarkBg = Color(0xFF1A1A2E)
val HeaderBg = Color(0xFF16213E)
val CardBg = Color(0xFF0F3460)
val PrimaryBlue = Color(0xFF00B0FF)
val GreenOk = Color(0xFF00E676)
val RedBad = Color(0xFFFF1744)

@Composable
fun CompanionAppUI(
    devices: List<OsmDevice>,
    onConnect: (OsmDevice) -> Unit,
    onDisconnect: (String) -> Unit,
    onSendText: (String, String) -> Unit,  // deviceId, text
) {
    var selectedDeviceId by remember { mutableStateOf<String?>(null) }
    val selectedDevice = devices.find { it.id == selectedDeviceId }

    MaterialTheme(
        colorScheme = darkColorScheme(
            primary = PrimaryBlue,
            background = DarkBg,
            surface = HeaderBg,
            onBackground = Color.White,
            onSurface = Color.White,
        )
    ) {
        Row(Modifier.fillMaxSize().background(DarkBg)) {
            // Left panel: device list
            DeviceListPanel(
                devices = devices,
                selectedId = selectedDeviceId,
                onSelect = { selectedDeviceId = it.id },
                onConnect = onConnect,
                onDisconnect = onDisconnect,
                modifier = Modifier.width(220.dp).fillMaxHeight()
            )

            // Right panel: device detail
            if (selectedDevice != null) {
                DeviceDetailPanel(
                    device = selectedDevice,
                    onSendText = { text -> onSendText(selectedDevice.id, text) },
                    modifier = Modifier.weight(1f).fillMaxHeight()
                )
            } else {
                Box(Modifier.weight(1f).fillMaxHeight(), contentAlignment = Alignment.Center) {
                    Text("Select an OSM device", color = Color.Gray, fontSize = 14.sp)
                }
            }
        }
    }
}

@Composable
fun DeviceListPanel(
    devices: List<OsmDevice>,
    selectedId: String?,
    onSelect: (OsmDevice) -> Unit,
    onConnect: (OsmDevice) -> Unit,
    onDisconnect: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    Column(modifier.background(HeaderBg).padding(8.dp)) {
        Text("OSM Devices", fontWeight = FontWeight.Bold, color = PrimaryBlue, fontSize = 16.sp)
        Spacer(Modifier.height(8.dp))

        if (devices.isEmpty()) {
            Text("Scanning...", color = Color.Gray, fontSize = 12.sp)
        }

        LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            items(devices) { device ->
                val isSelected = device.id == selectedId
                Card(
                    modifier = Modifier.fillMaxWidth().clickable { onSelect(device) },
                    colors = CardDefaults.cardColors(
                        containerColor = if (isSelected) CardBg else HeaderBg
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Row(
                        Modifier.padding(8.dp).fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        // Status dot
                        Box(
                            Modifier.size(10.dp).clip(CircleShape).background(
                                when (device.state) {
                                    ConnectionState.CONNECTED -> GreenOk
                                    ConnectionState.CONNECTING -> Color.Yellow
                                    ConnectionState.DISCONNECTED -> RedBad
                                }
                            )
                        )
                        Spacer(Modifier.width(8.dp))
                        Column(Modifier.weight(1f)) {
                            Text(device.name, fontWeight = FontWeight.Medium, fontSize = 13.sp)
                            Text(
                                when (device.state) {
                                    ConnectionState.CONNECTED -> "Connected"
                                    ConnectionState.CONNECTING -> "Connecting..."
                                    ConnectionState.DISCONNECTED -> "Disconnected"
                                },
                                fontSize = 10.sp,
                                color = Color.Gray
                            )
                        }
                        when (device.state) {
                            ConnectionState.DISCONNECTED -> {
                                TextButton(onClick = { onConnect(device) }) {
                                    Text("Connect", fontSize = 10.sp)
                                }
                            }
                            ConnectionState.CONNECTED -> {
                                TextButton(onClick = { onDisconnect(device.id) }) {
                                    Text("Drop", fontSize = 10.sp, color = RedBad)
                                }
                            }
                            else -> {}
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun DeviceDetailPanel(
    device: OsmDevice,
    onSendText: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    var inputText by remember { mutableStateOf("") }
    val clipboardManager = LocalClipboardManager.current

    Column(modifier.padding(12.dp)) {
        // Header
        Text("${device.name}", fontWeight = FontWeight.Bold, color = PrimaryBlue, fontSize = 16.sp)
        Spacer(Modifier.height(8.dp))

        // Received from OSM (outbox to user)
        Text("Received from OSM", fontWeight = FontWeight.Medium, fontSize = 13.sp, color = GreenOk)
        Spacer(Modifier.height(4.dp))
        LazyColumn(
            Modifier.weight(1f).fillMaxWidth()
                .background(HeaderBg, RoundedCornerShape(8.dp))
                .padding(8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            val fromOsm = device.inbox.filter { it.direction == CipherMessage.Direction.FROM_OSM }
            if (fromOsm.isEmpty()) {
                item {
                    Text("No messages yet", color = Color.Gray, fontSize = 12.sp)
                }
            }
            items(fromOsm.reversed()) { msg ->
                Card(
                    colors = CardDefaults.cardColors(containerColor = CardBg),
                    shape = RoundedCornerShape(6.dp)
                ) {
                    Row(Modifier.padding(8.dp).fillMaxWidth(),
                        verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            msg.text.take(80) + if (msg.text.length > 80) "..." else "",
                            fontSize = 11.sp,
                            modifier = Modifier.weight(1f),
                            color = Color.White
                        )
                        TextButton(onClick = {
                            clipboardManager.setText(AnnotatedString(msg.text))
                        }) {
                            Text("Copy", fontSize = 10.sp)
                        }
                    }
                }
            }
        }

        Spacer(Modifier.height(8.dp))

        // Send to OSM
        Text("Send to OSM", fontWeight = FontWeight.Medium, fontSize = 13.sp, color = PrimaryBlue)
        Spacer(Modifier.height(4.dp))
        OutlinedTextField(
            value = inputText,
            onValueChange = { inputText = it },
            modifier = Modifier.fillMaxWidth().height(100.dp),
            placeholder = { Text("Paste ciphertext here...", fontSize = 12.sp) },
            colors = OutlinedTextFieldDefaults.colors(
                focusedBorderColor = PrimaryBlue,
                unfocusedBorderColor = Color.Gray,
                focusedTextColor = Color.White,
                unfocusedTextColor = Color.White,
            )
        )
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    val clip = clipboardManager.getText()?.text ?: ""
                    if (clip.isNotEmpty()) inputText = clip
                },
                colors = ButtonDefaults.buttonColors(containerColor = CardBg)
            ) {
                Text("Paste from clipboard", fontSize = 11.sp)
            }
            Button(
                onClick = {
                    if (inputText.isNotBlank()) {
                        onSendText(inputText)
                        inputText = ""
                    }
                },
                enabled = device.state == ConnectionState.CONNECTED && inputText.isNotBlank(),
                colors = ButtonDefaults.buttonColors(containerColor = PrimaryBlue)
            ) {
                Text(
                    if (device.state == ConnectionState.CONNECTED) "Send" else "Queue",
                    fontSize = 11.sp
                )
            }
        }
    }
}
