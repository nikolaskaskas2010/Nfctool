package com.nfctool.app

/**
 * Interprets the raw memory image of a MIFARE Ultralight / NTAG style tag:
 * UID & BCC check, Capability Container, static + dynamic lock bytes, and the
 * EV1 configuration pages (AUTH0 / PROT / CFGLCK / AUTHLIM).
 *
 * This is a read-only explainer. It tells the user what a tag's protection is
 * currently set to; it does not defeat any of it.
 */
object TagAnalyzer {

    fun analyze(data: ByteArray): String {
        val pages = data.size / 4
        val sb = StringBuilder()
        sb.append("Pages read: ").append(pages)
            .append("  (").append(data.size).append(" bytes)\n")

        if (pages < 4) {
            sb.append("Too few pages to interpret headers.\n")
            return sb.toString()
        }

        // ---- UID + BCC ----
        val uid = byteArrayOf(
            data[0], data[1], data[2], data[4], data[5], data[6], data[7]
        )
        sb.append("UID (7B): ").append(HexUtils.toHex(uid)).append('\n')
        val bcc0 = data[3].toInt() and 0xFF
        val bcc0calc = (0x88 xor (data[0].toInt() and 0xFF) xor
            (data[1].toInt() and 0xFF) xor (data[2].toInt() and 0xFF)) and 0xFF
        val bcc1 = data[8].toInt() and 0xFF
        val bcc1calc = ((data[4].toInt() and 0xFF) xor (data[5].toInt() and 0xFF) xor
            (data[6].toInt() and 0xFF) xor (data[7].toInt() and 0xFF)) and 0xFF
        sb.append("BCC0: ").append(ok(bcc0, bcc0calc))
            .append("   BCC1: ").append(ok(bcc1, bcc1calc)).append('\n')

        // ---- Static lock bytes (page 2, bytes 2-3) ----
        val sl0 = data[10].toInt() and 0xFF
        val sl1 = data[11].toInt() and 0xFF
        sb.append("Static lock bytes (pg02.2-3): ")
            .append(String.format("%02X %02X", sl0, sl1))
            .append(if (sl0 == 0 && sl1 == 0) "  -> nothing statically locked\n"
                    else "  -> some pages permanently locked (OTP, irreversible)\n")

        // ---- Capability Container (page 3) ----
        if (pages > 3) {
            val cc = data.copyOfRange(12, 16)
            sb.append("CC (pg03): ").append(HexUtils.toHex(cc))
            if ((cc[0].toInt() and 0xFF) == 0xE1) {
                val sizeBytes = (cc[2].toInt() and 0xFF) * 8
                val roNibble = cc[3].toInt() and 0x0F
                sb.append("  -> NDEF, ~").append(sizeBytes).append(" B, ")
                    .append(if (roNibble == 0) "read+write" else "read-only (CC)")
            }
            sb.append('\n')
        }

        // ---- EV1 configuration pages (last 4 pages: lock, CFG0, CFG1, PWD, PACK) ----
        // For MF0UL21 the config lives at 0x24..0x28. We locate CFG0/CFG1 relative
        // to the end of the image, which is the robust way across EV1 variants.
        if (pages >= 5) {
            // Dynamic lock bytes are the page just before CFG0 on EV1 parts.
            val cfg0 = (pages - 4) * 4   // CFG0 page start (AUTH0 in byte 3)
            val cfg1 = (pages - 3) * 4   // CFG1 page start (ACCESS in byte 0)
            if (cfg1 + 1 <= data.size) {
                val auth0 = data[cfg0 + 3].toInt() and 0xFF
                val access = data[cfg1].toInt() and 0xFF
                val prot = (access and 0x80) != 0
                val cfglck = (access and 0x40) != 0
                val authlim = access and 0x07
                sb.append("AUTH0: 0x").append(String.format("%02X", auth0))
                    .append(if (auth0 >= pages) "  -> password protection effectively OFF\n"
                            else "  -> password required from page 0x" +
                                 String.format("%02X", auth0) + " onward\n")
                sb.append("PROT: ").append(if (prot) "read+write protected"
                                           else "write-only protected (reads open)")
                    .append('\n')
                sb.append("CFGLCK: ").append(if (cfglck) "config LOCKED" else "config writable")
                    .append("   AUTHLIM: ")
                    .append(if (authlim == 0) "unlimited attempts" else "$authlim attempts then lockout")
                    .append('\n')
            }
        }

        // ---- Repeated-block heuristic (hints at encrypted/structured payload) ----
        findRepeatedBlocks(data)?.let { sb.append(it).append('\n') }

        return sb.toString()
    }

    private fun ok(actual: Int, expected: Int): String =
        if (actual == expected) String.format("%02X ok", actual)
        else String.format("%02X (expected %02X!)", actual, expected)

    /** Flags identical 16-byte blocks, a common fingerprint of ECB-style encoding. */
    private fun findRepeatedBlocks(data: ByteArray): String? {
        val block = 16
        val zero = "0".repeat(block * 2)
        val seen = HashMap<String, Int>()
        var i = 0
        while (i + block <= data.size) {
            val key = HexUtils.toHex(data.copyOfRange(i, i + block), "")
            val firstPage = i / 4
            val prev = seen[key]
            if (prev != null && key != zero) {
                return "Note: pages ${prev}-${prev + 3} == pages ${firstPage}-${firstPage + 3} " +
                    "(repeated block -> payload looks encrypted/encoded, not plaintext NDEF)"
            }
            seen[key] = firstPage
            i += block
        }
        return null
    }
}
