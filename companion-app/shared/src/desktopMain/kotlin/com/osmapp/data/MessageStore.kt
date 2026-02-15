package com.osmapp.data

import com.osmapp.model.CipherMessage
import java.io.File

/**
 * Persists CA inbox/outbox messages to JSON files.
 * Each OSM device gets its own directory under the store root.
 * Max 50 inbox and 200 outbox messages per device.
 */
class MessageStore(baseDir: String = System.getProperty("user.home") + "/.osm-ca") {

    private val root = File(baseDir).also { it.mkdirs() }

    companion object {
        private const val MAX_INBOX = 50
        private const val MAX_OUTBOX = 200
    }

    private fun deviceDir(deviceId: String): File =
        File(root, deviceId.replace(Regex("[^a-zA-Z0-9_-]"), "_")).also { it.mkdirs() }

    fun saveInbox(deviceId: String, messages: List<CipherMessage>) {
        val file = File(deviceDir(deviceId), "inbox.json")
        val trimmed = messages.takeLast(MAX_INBOX)
        file.writeText(serializeMessages(trimmed))
    }

    fun loadInbox(deviceId: String): List<CipherMessage> {
        val file = File(deviceDir(deviceId), "inbox.json")
        if (!file.exists()) return emptyList()
        return deserializeMessages(file.readText())
    }

    fun saveOutbox(deviceId: String, messages: List<CipherMessage>) {
        val file = File(deviceDir(deviceId), "outbox.json")
        val trimmed = messages.takeLast(MAX_OUTBOX)
        file.writeText(serializeMessages(trimmed))
    }

    fun loadOutbox(deviceId: String): List<CipherMessage> {
        val file = File(deviceDir(deviceId), "outbox.json")
        if (!file.exists()) return emptyList()
        return deserializeMessages(file.readText())
    }

    private fun serializeMessages(messages: List<CipherMessage>): String {
        val sb = StringBuilder("[\n")
        messages.forEachIndexed { i, msg ->
            val escaped = msg.text.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")
            sb.append("  {\"text\":\"$escaped\"")
            sb.append(",\"ts\":${msg.timestamp}")
            sb.append(",\"dir\":\"${msg.direction.name}\"")
            sb.append(",\"id\":\"${msg.msgId}\"")
            sb.append(",\"del\":${msg.delivered}}")
            if (i < messages.size - 1) sb.append(",")
            sb.append("\n")
        }
        sb.append("]\n")
        return sb.toString()
    }

    private fun deserializeMessages(json: String): List<CipherMessage> {
        val messages = mutableListOf<CipherMessage>()
        // Simple JSON parsing — find each object between { }
        var i = 0
        while (i < json.length) {
            val start = json.indexOf('{', i)
            if (start < 0) break
            val end = json.indexOf('}', start)
            if (end < 0) break
            val obj = json.substring(start + 1, end)
            i = end + 1

            val text = extractString(obj, "text") ?: continue
            val ts = extractLong(obj, "ts") ?: System.currentTimeMillis()
            val dir = extractString(obj, "dir")?.let {
                try { CipherMessage.Direction.valueOf(it) } catch (_: Exception) { CipherMessage.Direction.FROM_OSM }
            } ?: CipherMessage.Direction.FROM_OSM
            val msgId = extractString(obj, "id") ?: ""
            val delivered = obj.contains("\"del\":true")

            messages.add(CipherMessage(
                text = text.replace("\\n", "\n").replace("\\\"", "\"").replace("\\\\", "\\"),
                timestamp = ts, direction = dir, msgId = msgId, delivered = delivered
            ))
        }
        return messages
    }

    private fun extractString(obj: String, key: String): String? {
        val keyPattern = "\"$key\":\""
        val start = obj.indexOf(keyPattern)
        if (start < 0) return null
        val valueStart = start + keyPattern.length
        val sb = StringBuilder()
        var j = valueStart
        while (j < obj.length) {
            if (obj[j] == '\\' && j + 1 < obj.length) {
                sb.append(obj[j])
                sb.append(obj[j + 1])
                j += 2
            } else if (obj[j] == '"') {
                break
            } else {
                sb.append(obj[j])
                j++
            }
        }
        return sb.toString()
    }

    private fun extractLong(obj: String, key: String): Long? {
        val keyPattern = "\"$key\":"
        val start = obj.indexOf(keyPattern)
        if (start < 0) return null
        val valueStart = start + keyPattern.length
        val numStr = obj.substring(valueStart).takeWhile { it.isDigit() || it == '-' }
        return numStr.toLongOrNull()
    }
}
