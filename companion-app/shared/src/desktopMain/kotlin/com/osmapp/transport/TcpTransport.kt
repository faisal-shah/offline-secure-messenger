package com.osmapp.transport

import com.osmapp.model.ConnectionState
import com.osmapp.model.OsmDevice
import kotlinx.coroutines.*
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * TCP transport for desktop simulator.
 * Scans localhost ports 19200-19209 for running OSM instances.
 * Uses the same framing as the OSM TCP server:
 *   [4 bytes msg_len][2 bytes char_uuid][packet_data]
 * Fragmentation: [1 byte flags][2 bytes seq][payload]
 */
class TcpTransport(private val portFilter: Int? = null) : Transport {

    companion object {
        private const val PORT_START = 19200
        private const val PORT_END = 19209
        private const val CONNECT_TIMEOUT_MS = 200
        private const val CHAR_UUID_TX: Short = 0xFE02.toShort()
        private const val CHAR_UUID_RX: Short = 0xFE03.toShort()
        private const val FRAG_FLAG_START: Byte = 0x01
        private const val FRAG_FLAG_END: Byte = 0x02
        private const val MTU = 200
    }

    private val connections = mutableMapOf<String, Socket>()
    private val readers = mutableMapOf<String, Job>()
    private var discoveryJob: Job? = null

    private var messageListener: ((String, ByteArray) -> Unit)? = null
    private var connectionListener: ((String, Boolean) -> Unit)? = null
    private var discoveryListener: ((OsmDevice) -> Unit)? = null

    override suspend fun startDiscovery() {
        discoveryJob?.cancel()
        discoveryJob = CoroutineScope(Dispatchers.IO).launch {
            while (isActive) {
                val ports = if (portFilter != null) portFilter..portFilter else PORT_START..PORT_END
                for (port in ports) {
                    try {
                        val id = "osm-$port"
                        // Skip probe if already connected
                        if (connections.containsKey(id)) {
                            discoveryListener?.invoke(OsmDevice(
                                id = id, name = "OSM :$port", port = port,
                                state = ConnectionState.CONNECTED
                            ))
                        } else {
                            val socket = Socket()
                            socket.connect(InetSocketAddress("127.0.0.1", port), CONNECT_TIMEOUT_MS)
                            socket.close()
                            discoveryListener?.invoke(OsmDevice(
                                id = id, name = "OSM :$port", port = port,
                                state = ConnectionState.DISCONNECTED
                            ))
                        }
                    } catch (_: IOException) {
                        // Port not listening
                    }
                }
                delay(3000)
            }
        }
    }

    override fun stopDiscovery() {
        discoveryJob?.cancel()
        discoveryJob = null
    }

    override suspend fun connect(device: OsmDevice): Boolean {
        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()
                socket.connect(InetSocketAddress("127.0.0.1", device.port), 1000)
                socket.tcpNoDelay = true
                connections[device.id] = socket
                connectionListener?.invoke(device.id, true)

                // Start reader coroutine
                readers[device.id] = CoroutineScope(Dispatchers.IO).launch {
                    readLoop(device.id, socket)
                }
                true
            } catch (e: IOException) {
                println("[TcpTransport] Connect failed: ${e.message}")
                false
            }
        }
    }

    override fun disconnect(deviceId: String) {
        readers[deviceId]?.cancel()
        readers.remove(deviceId)
        connections[deviceId]?.close()
        connections.remove(deviceId)
        connectionListener?.invoke(deviceId, false)
    }

    override suspend fun send(deviceId: String, data: ByteArray): Boolean {
        val socket = connections[deviceId] ?: return false
        return withContext(Dispatchers.IO) {
            try {
                sendFragmented(socket, CHAR_UUID_RX, data)
                true
            } catch (e: IOException) {
                println("[TcpTransport] Send failed: ${e.message}")
                disconnect(deviceId)
                false
            }
        }
    }

    override fun onMessage(listener: (String, ByteArray) -> Unit) {
        messageListener = listener
    }

    override fun onConnectionChange(listener: (String, Boolean) -> Unit) {
        connectionListener = listener
    }

    override fun onDeviceDiscovered(listener: (OsmDevice) -> Unit) {
        discoveryListener = listener
    }

    /** Send data with fragmentation protocol. */
    private fun sendFragmented(socket: Socket, charUuid: Short, data: ByteArray) {
        val maxPayload = MTU - 3 // 1 flags + 2 seq
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

            // TCP frame: [4B len][2B uuid][frag_data]
            val frameBuf = ByteBuffer.allocate(6 + fragData.size)
                .order(ByteOrder.BIG_ENDIAN)
            frameBuf.putInt(fragData.size)
            frameBuf.putShort(charUuid)
            frameBuf.put(fragData)

            socket.getOutputStream().write(frameBuf.array())
            offset += chunk
            seq++
        }
        socket.getOutputStream().flush()
    }

    /** Read incoming TCP frames and reassemble fragmented messages. */
    private suspend fun readLoop(deviceId: String, socket: Socket) {
        val reassemblyBuf = ByteArray(4096)
        var reassemblyLen = 0
        var expectedSeq: Short = 0
        var active = false

        try {
            val input = socket.getInputStream()
            val headerBuf = ByteArray(6)

            while (currentCoroutineContext().isActive) {
                // Read TCP frame header
                var read = 0
                while (read < 6) {
                    val n = input.read(headerBuf, read, 6 - read)
                    if (n <= 0) return
                    read += n
                }

                val hdr = ByteBuffer.wrap(headerBuf).order(ByteOrder.BIG_ENDIAN)
                val msgLen = hdr.int
                val charUuid = hdr.short

                // Read payload
                val payload = ByteArray(msgLen)
                read = 0
                while (read < msgLen) {
                    val n = input.read(payload, read, msgLen - read)
                    if (n <= 0) return
                    read += n
                }

                // Parse fragment
                if (msgLen < 3) continue
                val fragBuf = ByteBuffer.wrap(payload).order(ByteOrder.LITTLE_ENDIAN)
                val flags = fragBuf.get()
                val seq = fragBuf.short

                if ((flags.toInt() and FRAG_FLAG_START.toInt()) != 0) {
                    reassemblyLen = 0
                    expectedSeq = 0
                    active = true
                    // Skip 2-byte total_len
                    if (fragBuf.remaining() >= 2) fragBuf.short
                }

                if (!active || seq != expectedSeq) {
                    active = false
                    continue
                }

                val payloadData = ByteArray(fragBuf.remaining())
                fragBuf.get(payloadData)
                System.arraycopy(payloadData, 0, reassemblyBuf, reassemblyLen, payloadData.size)
                reassemblyLen += payloadData.size
                expectedSeq++

                if ((flags.toInt() and FRAG_FLAG_END.toInt()) != 0) {
                    val completeMessage = reassemblyBuf.copyOf(reassemblyLen)
                    messageListener?.invoke(deviceId, completeMessage)
                    active = false
                    reassemblyLen = 0
                }
            }
        } catch (e: IOException) {
            // Connection lost
        } finally {
            connectionListener?.invoke(deviceId, false)
            connections.remove(deviceId)
        }
    }
}
