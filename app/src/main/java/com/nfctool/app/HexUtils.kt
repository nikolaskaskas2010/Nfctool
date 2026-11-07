package com.nfctool.app

/** Small helpers for hex formatting and page-oriented dumps. */
object HexUtils {

    private val HEX = "0123456789ABCDEF".toCharArray()

    fun toHex(bytes: ByteArray?, separator: String = " "): String {
        if (bytes == null || bytes.isEmpty()) return ""
        val sb = StringBuilder(bytes.size * 3)
        for ((i, b) in bytes.withIndex()) {
            val v = b.toInt() and 0xFF
            sb.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
            if (i < bytes.size - 1) sb.append(separator)
        }
        return sb.toString()
    }

    fun toAscii(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(if (v in 0x20..0x7E) v.toChar() else '.')
        }
        return sb.toString()
    }

    /** Parse a hex string such as "FF FF FF FF" or "ffffffff" into bytes. */
    fun parseHex(input: String): ByteArray? {
        val clean = input.replace(Regex("[^0-9A-Fa-f]"), "")
        if (clean.isEmpty() || clean.length % 2 != 0) return null
        val out = ByteArray(clean.length / 2)
        var i = 0
        while (i < clean.length) {
            out[i / 2] = clean.substring(i, i + 2).toInt(16).toByte()
            i += 2
        }
        return out
    }

    /**
     * Render a full memory image as an annotated page dump:
     * `pg 04: 10 A1 66 67   .Afg`
     */
    fun pageDump(data: ByteArray, bytesPerPage: Int = 4): String {
        val sb = StringBuilder()
        var page = 0
        var i = 0
        while (i < data.size) {
            val end = minOf(i + bytesPerPage, data.size)
            val slice = data.copyOfRange(i, end)
            sb.append(String.format("pg %02d (0x%02X):  ", page, page))
                .append(toHex(slice).padEnd(bytesPerPage * 3))
                .append("  ")
                .append(toAscii(slice))
                .append('\n')
            i = end
            page++
        }
        return sb.toString()
    }
}
