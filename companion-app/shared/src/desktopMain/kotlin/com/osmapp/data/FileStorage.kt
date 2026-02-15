package com.osmapp.data

import java.io.File

actual class FileStorage(baseDir: String = System.getProperty("user.home") + "/.osm-ca") {
    actual val rootDir: String = baseDir

    init { File(rootDir).mkdirs() }

    actual fun readFile(path: String): String? {
        val f = File(path)
        return if (f.exists()) f.readText() else null
    }

    actual fun writeFile(path: String, content: String) { File(path).writeText(content) }
    actual fun ensureDir(path: String) { File(path).mkdirs() }
    actual fun resolve(parent: String, child: String): String = File(parent, child).absolutePath
}

internal actual fun currentTimeMillis(): Long = System.currentTimeMillis()
