package com.nfctool.app

/**
 * A short list of PUBLICLY DOCUMENTED factory / transport default passwords for
 * MIFARE Ultralight EV1 and NTAG21x (4-byte PWD used by the PWD_AUTH command).
 *
 * Purpose: recover access to a tag YOU OWN that was left on, or reset to, a
 * factory/default password. This is intentionally NOT a brute-force engine:
 *
 *  - The PWD space is 32 bits (2^32 values). At the tag's real transceive speed
 *    (~5-50 ms per PWD_AUTH), an exhaustive search is on the order of years, so
 *    exhaustive brute force is neither provided nor practical on a phone.
 *  - A tag configured with a genuine, non-default password will NOT be recovered
 *    by this list, by design.
 *
 * The user may also supply a single candidate password to try manually.
 */
object PasswordDictionary {

    /** Each entry is exactly 4 bytes. */
    val DEFAULTS: List<ByteArray> = listOf(
        byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()), // NXP factory default
        byteArrayOf(0x00, 0x00, 0x00, 0x00),
        byteArrayOf(0x11, 0x22, 0x33, 0x44), // common demo value in vendor docs
        byteArrayOf(0x12, 0x34, 0x56, 0x78),
        byteArrayOf('P'.code.toByte(), 'W'.code.toByte(), 'D'.code.toByte(), 0x00), // "PWD\0"
    )

    fun describe(pwd: ByteArray): String = HexUtils.toHex(pwd)
}
