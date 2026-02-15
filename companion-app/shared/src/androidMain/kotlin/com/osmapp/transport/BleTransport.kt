package com.osmapp.transport

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.Build
import android.os.ParcelUuid
import com.osmapp.model.OsmDevice
import kotlinx.coroutines.*
import kotlinx.coroutines.channels.Channel
import java.security.MessageDigest
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import kotlin.coroutines.resume
import kotlin.coroutines.suspendCoroutine

/**
 * BLE GATT client transport for Android.
 * Connects to the OSM device's BLE peripheral and exchanges fragmented messages
 * using the same protocol as TcpTransport (byte-compatible with the OSM firmware).
 */
@SuppressLint("MissingPermission")
class BleTransport(private val context: Context) : Transport {

    companion object {
        val SERVICE_UUID: UUID = UUID.fromString("0000FE00-0000-1000-8000-00805F9B34FB")
        val TX_CHAR_UUID: UUID = UUID.fromString("0000FE02-0000-1000-8000-00805F9B34FB")   // OSM → CA (Notify)
        val RX_CHAR_UUID: UUID = UUID.fromString("0000FE03-0000-1000-8000-00805F9B34FB")   // CA → OSM (Write)
        val INFO_CHAR_UUID: UUID = UUID.fromString("0000FE05-0000-1000-8000-00805F9B34FB") // Read
        val CCC_DESCRIPTOR_UUID: UUID = UUID.fromString("00002902-0000-1000-8000-00805F9B34FB")

        // Fragmentation constants (must match OSM)
        private const val FRAG_FLAG_START: Byte = 0x01
        private const val FRAG_FLAG_END: Byte = 0x02
        private const val FRAG_FLAG_ACK: Byte = 0x04
        private const val MTU = 200
        private const val MAX_MSG_SIZE = 4096
        private const val ACK_ID_LEN = 8

        fun computeMsgId(data: ByteArray): ByteArray {
            val digest = MessageDigest.getInstance("SHA-512")
            return digest.digest(data).copyOf(ACK_ID_LEN)
        }
    }

    private data class GattConnection(
        val gatt: BluetoothGatt,
        val rxChar: BluetoothGattCharacteristic,
        val txChar: BluetoothGattCharacteristic
    )

    private class ReassemblyState {
        var buf = ByteArray(MAX_MSG_SIZE)
        var len = 0
        var expectedSeq: Int = 0
        var active = false
    }

    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val bluetoothAdapter: BluetoothAdapter? = bluetoothManager.adapter

    private val connections = mutableMapOf<String, GattConnection>()
    private val reassembly = mutableMapOf<String, ReassemblyState>()
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // BLE write serialization: only one GATT write operation at a time per device
    private val writeChannels = mutableMapOf<String, Channel<Unit>>()

    private var messageListener: ((String, ByteArray) -> Unit)? = null
    private var connectionListener: ((String, Boolean) -> Unit)? = null
    private var discoveryListener: ((OsmDevice) -> Unit)? = null
    private var ackListener: ((String, ByteArray) -> Unit)? = null

    private var scanner: BluetoothLeScanner? = null
    private var scanning = false

    // Continuation for connect() — resumed from gattCallback once setup is complete
    private val connectContinuations = mutableMapOf<String, CompletableDeferred<Boolean>>()

    // ── Scan ─────────────────────────────────────────────────────────────

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val address = result.device.address
            val name = result.device.name ?: "OSM $address"
            val device = OsmDevice(id = address, name = name, port = 0)
            discoveryListener?.invoke(device)
        }

        override fun onScanFailed(errorCode: Int) {
            println("[BleTransport] Scan failed: $errorCode")
        }
    }

    override suspend fun startDiscovery() {
        val adapter = bluetoothAdapter ?: run {
            println("[BleTransport] Bluetooth not available")
            return
        }
        scanner = adapter.bluetoothLeScanner ?: run {
            println("[BleTransport] BLE scanner not available")
            return
        }

        val filter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()

        scanner?.startScan(listOf(filter), settings, scanCallback)
        scanning = true
    }

    override fun stopDiscovery() {
        if (scanning) {
            scanner?.stopScan(scanCallback)
            scanning = false
        }
    }

    // ── Connect ──────────────────────────────────────────────────────────

    override suspend fun connect(device: OsmDevice): Boolean {
        val adapter = bluetoothAdapter ?: return false
        val bleDevice = adapter.getRemoteDevice(device.id) ?: return false

        // Set up deferred for this connection attempt
        val deferred = CompletableDeferred<Boolean>()
        connectContinuations[device.id] = deferred

        bleDevice.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)

        return try {
            withTimeout(15_000) { deferred.await() }
        } catch (e: TimeoutCancellationException) {
            println("[BleTransport] Connect timeout: ${device.id}")
            connectContinuations.remove(device.id)
            false
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {

        override fun onConnectionStateChange(gatt: BluetoothGatt, status: Int, newState: Int) {
            val deviceId = gatt.device.address
            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    gatt.discoverServices()
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    cleanupConnection(deviceId)
                    connectContinuations.remove(deviceId)?.complete(false)
                    connectionListener?.invoke(deviceId, false)
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt, status: Int) {
            val deviceId = gatt.device.address
            if (status != BluetoothGatt.GATT_SUCCESS) {
                gatt.disconnect()
                connectContinuations.remove(deviceId)?.complete(false)
                return
            }

            val service = gatt.getService(SERVICE_UUID)
            if (service == null) {
                println("[BleTransport] OSM service not found on $deviceId")
                gatt.disconnect()
                connectContinuations.remove(deviceId)?.complete(false)
                return
            }

            val txChar = service.getCharacteristic(TX_CHAR_UUID)
            val rxChar = service.getCharacteristic(RX_CHAR_UUID)
            if (txChar == null || rxChar == null) {
                println("[BleTransport] Required characteristics not found on $deviceId")
                gatt.disconnect()
                connectContinuations.remove(deviceId)?.complete(false)
                return
            }

            // Configure RX for write-no-response
            rxChar.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE

            // Subscribe to TX notifications
            gatt.setCharacteristicNotification(txChar, true)
            val cccDescriptor = txChar.getDescriptor(CCC_DESCRIPTOR_UUID)
            if (cccDescriptor != null) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeDescriptor(cccDescriptor, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE)
                } else {
                    @Suppress("DEPRECATION")
                    cccDescriptor.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
                    @Suppress("DEPRECATION")
                    gatt.writeDescriptor(cccDescriptor)
                }
            } else {
                // No CCC descriptor — proceed anyway, some stacks auto-enable
                onDescriptorWriteCompleted(gatt)
            }
        }

        override fun onDescriptorWrite(
            gatt: BluetoothGatt,
            descriptor: BluetoothGattDescriptor,
            status: Int
        ) {
            if (descriptor.uuid == CCC_DESCRIPTOR_UUID) {
                onDescriptorWriteCompleted(gatt)
            }
        }

        private fun onDescriptorWriteCompleted(gatt: BluetoothGatt) {
            // Request larger MTU for better throughput
            gatt.requestMtu(MTU + 3) // +3 for ATT header
        }

        override fun onMtuChanged(gatt: BluetoothGatt, mtu: Int, status: Int) {
            val deviceId = gatt.device.address
            val service = gatt.getService(SERVICE_UUID) ?: return
            val txChar = service.getCharacteristic(TX_CHAR_UUID) ?: return
            val rxChar = service.getCharacteristic(RX_CHAR_UUID) ?: return

            val conn = GattConnection(gatt, rxChar, txChar)
            connections[deviceId] = conn
            reassembly[deviceId] = ReassemblyState()
            writeChannels[deviceId] = Channel(1)

            connectionListener?.invoke(deviceId, true)
            connectContinuations.remove(deviceId)?.complete(true)
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic
        ) {
            if (characteristic.uuid != TX_CHAR_UUID) return
            val data = characteristic.value ?: return
            handleFragment(gatt.device.address, data)
        }

        // API 33+ variant
        override fun onCharacteristicChanged(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            value: ByteArray
        ) {
            if (characteristic.uuid != TX_CHAR_UUID) return
            handleFragment(gatt.device.address, value)
        }

        override fun onCharacteristicWrite(
            gatt: BluetoothGatt,
            characteristic: BluetoothGattCharacteristic,
            status: Int
        ) {
            val deviceId = gatt.device.address
            // Signal that the write completed so the next fragment can be sent
            writeChannels[deviceId]?.trySend(Unit)
        }
    }

    // ── Fragment reassembly (mirrors TcpTransport.readLoop) ──────────────

    private fun handleFragment(deviceId: String, data: ByteArray) {
        if (data.size < 3) return

        val fragBuf = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val flags = fragBuf.get()
        val seq = fragBuf.short.toInt() and 0xFFFF

        // Handle incoming ACK from OSM
        if ((flags.toInt() and FRAG_FLAG_ACK.toInt()) != 0) {
            if (fragBuf.remaining() >= ACK_ID_LEN) {
                val msgId = ByteArray(ACK_ID_LEN)
                fragBuf.get(msgId)
                ackListener?.invoke(deviceId, msgId)
            }
            return
        }

        val state = reassembly[deviceId] ?: return

        if ((flags.toInt() and FRAG_FLAG_START.toInt()) != 0) {
            state.len = 0
            state.expectedSeq = 0
            state.active = true
            // Skip 2-byte total_len field
            if (fragBuf.remaining() >= 2) fragBuf.short
        }

        if (!state.active || seq != state.expectedSeq) {
            state.active = false
            return
        }

        val payloadData = ByteArray(fragBuf.remaining())
        fragBuf.get(payloadData)

        if (state.len + payloadData.size > MAX_MSG_SIZE) {
            state.active = false
            return
        }

        System.arraycopy(payloadData, 0, state.buf, state.len, payloadData.size)
        state.len += payloadData.size
        state.expectedSeq++

        if ((flags.toInt() and FRAG_FLAG_END.toInt()) != 0) {
            val completeMessage = state.buf.copyOf(state.len)
            state.active = false
            state.len = 0

            // Send ACK back to OSM
            val msgId = computeMsgId(completeMessage)
            scope.launch {
                try {
                    sendAck(deviceId, msgId)
                } catch (_: Exception) { /* ignore ACK send failure */ }
            }

            messageListener?.invoke(deviceId, completeMessage)
        }
    }

    // ── Send ─────────────────────────────────────────────────────────────

    override suspend fun send(deviceId: String, data: ByteArray): Boolean {
        val conn = connections[deviceId] ?: return false
        return withContext(Dispatchers.IO) {
            try {
                sendFragmented(deviceId, conn, data)
                true
            } catch (e: Exception) {
                println("[BleTransport] Send failed: ${e.message}")
                disconnect(deviceId)
                false
            }
        }
    }

    /**
     * Fragment and write data to the RX characteristic.
     * Waits for each write callback before sending the next fragment.
     */
    private suspend fun sendFragmented(deviceId: String, conn: GattConnection, data: ByteArray) {
        val maxPayload = MTU - 3  // 1 flags + 2 seq
        var offset = 0
        var seq: Short = 0

        while (offset < data.size) {
            val isStart = offset == 0
            val overhead = if (isStart) 2 else 0  // 2-byte total_len in START
            val chunk = minOf(data.size - offset, maxPayload - overhead)
            val isEnd = (offset + chunk >= data.size)

            val fragBuf = ByteBuffer.allocate(3 + overhead + chunk)
                .order(ByteOrder.LITTLE_ENDIAN)

            var flags: Byte = 0
            if (isStart) flags = (flags.toInt() or FRAG_FLAG_START.toInt()).toByte()
            if (isEnd) flags = (flags.toInt() or FRAG_FLAG_END.toInt()).toByte()

            fragBuf.put(flags)
            fragBuf.putShort(seq)
            if (isStart) {
                fragBuf.putShort(data.size.toShort())
            }
            fragBuf.put(data, offset, chunk)

            val fragData = fragBuf.array()

            writeCharacteristic(conn.gatt, conn.rxChar, fragData, deviceId)

            offset += chunk
            seq++
        }
    }

    /** Send an ACK frame for a received message. */
    private suspend fun sendAck(deviceId: String, msgId: ByteArray) {
        val conn = connections[deviceId] ?: return

        val fragBuf = ByteBuffer.allocate(3 + ACK_ID_LEN)
            .order(ByteOrder.LITTLE_ENDIAN)
        fragBuf.put(FRAG_FLAG_ACK)
        fragBuf.putShort(0)
        fragBuf.put(msgId, 0, ACK_ID_LEN)

        writeCharacteristic(conn.gatt, conn.rxChar, fragBuf.array(), deviceId)
    }

    /**
     * Write a value to a characteristic and wait for the onCharacteristicWrite callback.
     * Serializes BLE writes — only one outstanding GATT operation at a time per device.
     */
    private suspend fun writeCharacteristic(
        gatt: BluetoothGatt,
        characteristic: BluetoothGattCharacteristic,
        value: ByteArray,
        deviceId: String
    ) {
        val writeDone = writeChannels[deviceId] ?: return
        // Drain any stale signals
        while (writeDone.tryReceive().isSuccess) { /* drain */ }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            gatt.writeCharacteristic(
                characteristic,
                value,
                BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            )
        } else {
            @Suppress("DEPRECATION")
            characteristic.value = value
            characteristic.writeType = BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE
            @Suppress("DEPRECATION")
            gatt.writeCharacteristic(characteristic)
        }

        // Wait for onCharacteristicWrite callback (with timeout)
        withTimeout(5_000) {
            writeDone.receive()
        }
    }

    // ── Disconnect ───────────────────────────────────────────────────────

    override fun disconnect(deviceId: String) {
        val conn = connections[deviceId]
        if (conn != null) {
            conn.gatt.disconnect()
            conn.gatt.close()
        }
        cleanupConnection(deviceId)
        connectionListener?.invoke(deviceId, false)
    }

    private fun cleanupConnection(deviceId: String) {
        connections.remove(deviceId)
        reassembly.remove(deviceId)
        writeChannels.remove(deviceId)?.close()
    }

    // ── Listeners ────────────────────────────────────────────────────────

    override fun onMessage(listener: (deviceId: String, data: ByteArray) -> Unit) {
        messageListener = listener
    }

    override fun onConnectionChange(listener: (deviceId: String, connected: Boolean) -> Unit) {
        connectionListener = listener
    }

    override fun onDeviceDiscovered(listener: (OsmDevice) -> Unit) {
        discoveryListener = listener
    }

    override fun onAck(listener: (deviceId: String, msgId: ByteArray) -> Unit) {
        ackListener = listener
    }
}
