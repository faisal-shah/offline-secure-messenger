package com.osmapp.data

expect class FileStorage {
    fun readFile(path: String): String?
    fun writeFile(path: String, content: String)
    fun ensureDir(path: String)
    fun resolve(parent: String, child: String): String
    val rootDir: String
}
