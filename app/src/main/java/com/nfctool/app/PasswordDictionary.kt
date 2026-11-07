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

    /**
     * Candidate passwords derived from the tag UID using COMMON, PUBLISHED weak
     * schemes. Many low-end deployments set PWD = some trivial transform of the
     * UID instead of a random value; this recovers those for the tag's owner.
     *
     * This is a small, finite candidate set (not an exhaustive search). It can
     * only open a tag whose password was derived by one of these known weak
     * schemes; it cannot open a tag with a properly randomised password.
     *
     * @param uid the 7-byte UID (as returned by Tag.getId()).
     */
    fun deriveFromUid(uid: ByteArray): List<ByteArray> {
        if (uid.size < 7) return emptyList()
        val out = LinkedHashSet<List<Byte>>() // de-dupe by value

        val first4 = byteArrayOf(uid[0], uid[1], uid[2], uid[3])
        val last4 = byteArrayOf(uid[3], uid[4], uid[5], uid[6])

        fun add(b: ByteArray) { out.add(b.toList()) }
        fun xorAll(b: ByteArray, k: Int) =
            ByteArray(4) { (b[it].toInt() xor k).toByte() }
        fun rev(b: ByteArray) = byteArrayOf(b[3], b[2], b[1], b[0])

        add(first4)
        add(last4)
        add(rev(first4))
        add(rev(last4))
        add(xorAll(first4, 0xFF))
        add(xorAll(last4, 0xFF))
        add(xorAll(first4, 0xAA))
        add(xorAll(last4, 0x55))

        return out.map { it.toByteArray() }
    }
}
