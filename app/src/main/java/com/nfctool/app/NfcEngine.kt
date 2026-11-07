package com.nfctool.app

import android.nfc.FormatException
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.Tag
import android.nfc.tech.MifareUltralight
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import android.nfc.tech.NfcA
import java.io.IOException

/**
 * Core NFC operations for NfcA / MifareUltralight / NdefFormatable (and generic
 * Ndef) tags. Every method returns a human-readable log string; failures are
 * reported, never hidden.
 */
class NfcEngine {

    // ---- command bytes (NXP Ultralight / NTAG) ----
    private val CMD_READ = 0x30.toByte()        // read 4 pages (16 bytes)
    private val CMD_FAST_READ = 0x3A.toByte()   // read a page range (EV1/NTAG)
    private val CMD_WRITE = 0xA2.toByte()        // write 1 page (4 bytes)
    private val CMD_GET_VERSION = 0x60.toByte()
    private val CMD_PWD_AUTH = 0x1B.toByte()

    // -------------------------------------------------------------------------
    // READ / DUMP
    // -------------------------------------------------------------------------

    fun identify(tag: Tag): String {
        val sb = StringBuilder()
        sb.append("UID: ").append(HexUtils.toHex(tag.id)).append('\n')
        sb.append("Tech: ").append(tag.techList.joinToString(", ") {
            it.substringAfterLast('.')
        }).append('\n')

        NfcA.get(tag)?.let { a ->
            sb.append(String.format("ATQA: %s  SAK: %02X\n",
                HexUtils.toHex(a.atqa), a.sak))
        }
        MifareUltralight.get(tag)?.let {
            sb.append("MifareUltralight type: ")
                .append(ultralightTypeName(it.type)).append('\n')
        }
        return sb.toString()
    }

    /** Full page dump via low-level READ, falling back page-by-page on error. */
    fun dump(tag: Tag): String {
        val sb = StringBuilder(identify(tag))
        val a = NfcA.get(tag) ?: return sb.append("No NfcA interface.\n").toString()
        try {
            a.connect()
            a.timeout = 300

            // GET_VERSION tells us the exact part (and therefore page count).
            val version = tryTransceive(a, byteArrayOf(CMD_GET_VERSION))
            if (version != null && version.size >= 8) {
                sb.append("GET_VERSION: ").append(HexUtils.toHex(version)).append('\n')
                sb.append("Part: ").append(decodeVersion(version)).append('\n')
            }

            val totalPages = guessPageCount(version)
            val mem = readAllPages(a, totalPages)
            sb.append("\n--- MEMORY DUMP ---\n")
            sb.append(HexUtils.pageDump(mem))
            sb.append("\n--- ANALYSIS ---\n")
            sb.append(TagAnalyzer.analyze(mem))

            // Decode any NDEF content if present.
            readNdef(tag)?.let { sb.append("\n--- NDEF ---\n").append(it) }
        } catch (e: Exception) {
            sb.append("Read error: ").append(e.message).append('\n')
        } finally {
            closeQuietly(a)
        }
        return sb.toString()
    }

    private fun readAllPages(a: NfcA, totalPages: Int): ByteArray {
        val out = ByteArray(totalPages * 4)
        var page = 0
        while (page < totalPages) {
            val resp = tryTransceive(a, byteArrayOf(CMD_READ, page.toByte()))
            if (resp == null || resp.size < 4) {
                // Can't read further (protected / end of memory). Stop cleanly.
                return out.copyOf(page * 4)
            }
            val n = minOf(16, (totalPages - page) * 4, resp.size)
            System.arraycopy(resp, 0, out, page * 4, n)
            page += 4
        }
        return out
    }

    // -------------------------------------------------------------------------
    // WRITE NDEF
    // -------------------------------------------------------------------------

    fun writeNdef(tag: Tag, text: String): String {
        val record = if (text.startsWith("http://") || text.startsWith("https://"))
            NdefRecord.createUri(text)
        else
            NdefRecord.createTextRecord("en", text)
        val message = NdefMessage(arrayOf(record))

        Ndef.get(tag)?.let { ndef ->
            return try {
                ndef.connect()
                if (!ndef.isWritable) return "Tag is not writable (locked)."
                if (ndef.maxSize < message.toByteArray().size)
                    return "Message too large: ${message.toByteArray().size} > ${ndef.maxSize}."
                ndef.writeNdefMessage(message)
                "Wrote NDEF (${message.toByteArray().size} bytes): \"$text\""
            } catch (e: Exception) {
                "NDEF write failed: ${e.message}"
            } finally { closeQuietly(ndef) }
        }

        NdefFormatable.get(tag)?.let { f ->
            return try {
                f.connect()
                f.format(message)
                "Formatted + wrote NDEF: \"$text\""
            } catch (e: Exception) {
                "Format-write failed: ${e.message}"
            } finally { closeQuietly(f) }
        }

        return "Tag does not support NDEF (not Ndef or NdefFormatable)."
    }

    // -------------------------------------------------------------------------
    // FORMAT (make an NdefFormatable tag into an empty NDEF tag)
    // -------------------------------------------------------------------------

    fun format(tag: Tag): String {
        val empty = NdefMessage(arrayOf(NdefRecord.createTextRecord("en", "")))
        NdefFormatable.get(tag)?.let { f ->
            return try {
                f.connect(); f.format(empty); "Formatted as empty NDEF."
            } catch (e: FormatException) { "Format failed: ${e.message}" }
            catch (e: IOException) { "I/O error: ${e.message}" }
            finally { closeQuietly(f) }
        }
        Ndef.get(tag)?.let {
            return "Tag is already NDEF-formatted; use Clear to empty it."
        }
        return "Tag is not NdefFormatable."
    }

    // -------------------------------------------------------------------------
    // CLEAR / ERASE (zero the user data pages)
    // -------------------------------------------------------------------------

    fun clear(tag: Tag): String {
        val a = NfcA.get(tag) ?: return "No NfcA interface to clear."
        val sb = StringBuilder()
        try {
            a.connect()
            a.timeout = 300
            val total = guessPageCount(tryTransceive(a, byteArrayOf(CMD_GET_VERSION)))
            // User data on Ultralight/NTAG starts at page 4. Leave UID, lock,
            // CC and config pages untouched; only clear the user area.
            val lastUserPage = total - 5  // stop before dynamic-lock/config block
            var cleared = 0
            for (page in 4..lastUserPage) {
                val resp = tryTransceive(
                    a, byteArrayOf(CMD_WRITE, page.toByte(), 0, 0, 0, 0)
                )
                if (resp == null) {
                    sb.append("Stopped at page $page (write-protected or locked).\n")
                    break
                }
                cleared++
            }
            sb.append("Cleared $cleared user pages (set to 00 00 00 00).\n")
        } catch (e: Exception) {
            sb.append("Clear error: ${e.message}\n")
        } finally { closeQuietly(a) }
        return sb.toString()
    }

    // -------------------------------------------------------------------------
    // MAKE READ-ONLY (permanent!)
    // -------------------------------------------------------------------------

    fun makeReadOnly(tag: Tag): String {
        Ndef.get(tag)?.let { ndef ->
            return try {
                ndef.connect()
                if (!ndef.canMakeReadOnly()) return "This tag cannot be made read-only."
                val okDone = ndef.makeReadOnly()
                if (okDone) "Tag is now PERMANENTLY read-only (lock bits set)."
                else "makeReadOnly() returned false."
            } catch (e: Exception) { "makeReadOnly failed: ${e.message}" }
            finally { closeQuietly(ndef) }
        }
        return "Tag is not NDEF; cannot use standard makeReadOnly()."
    }

    // -------------------------------------------------------------------------
    // PASSWORD RECOVERY (Ultralight EV1 / NTAG21x PWD_AUTH)
    // Tries, in order: an optional user-supplied candidate, the documented
    // default passwords, and candidates derived from the UID by common published
    // weak schemes. This is a small finite list; it is NOT an exhaustive
    // brute-forcer (see PasswordDictionary).
    // -------------------------------------------------------------------------

    fun recoverPassword(tag: Tag, userCandidate: ByteArray?): String {
        val sb = StringBuilder("Password recovery (PWD_AUTH)\n")
        sb.append("UID: ").append(HexUtils.toHex(tag.id)).append('\n')

        // Order: your manual candidate, then documented defaults, then candidates
        // derived from the UID by common published weak schemes. This is a small
        // finite list, NOT an exhaustive brute force.
        val candidates = LinkedHashSet<List<Byte>>()
        userCandidate?.let { if (it.size == 4) candidates.add(it.toList()) }
        PasswordDictionary.DEFAULTS.forEach { candidates.add(it.toList()) }
        PasswordDictionary.deriveFromUid(tag.id).forEach { candidates.add(it.toList()) }

        sb.append("Trying ").append(candidates.size).append(" candidates...\n")
        for (c in candidates) {
            val pwd = c.toByteArray()
            val pack = tryAuth(tag, pwd)
            if (pack != null) {
                sb.append("SUCCESS: password ")
                    .append(PasswordDictionary.describe(pwd))
                    .append("  PACK=").append(HexUtils.toHex(pack)).append('\n')
                return sb.toString()
            } else {
                sb.append("  no: ").append(PasswordDictionary.describe(pwd)).append('\n')
            }
        }
        sb.append("No candidate matched. ")
            .append("This tag's password is neither a documented default nor a simple\n")
            .append("UID-derived value, so it was provisioned properly and cannot be\n")
            .append("recovered here. (A 32-bit PWD is not exhaustively searchable on a\n")
            .append("phone in practical time, and this tool does not attempt that.)\n")
        return sb.toString()
    }

    /**
     * NFC Tools forgotten-password recovery: for a tag whose owner protected it
     * with the "NFC Tools" app, try a wordlist of candidate password STRINGS,
     * deriving each PWD as MD5(text)[0..3] (NFC Tools' scheme). On success the
     * human-readable password is returned so the owner can unprotect the tag in
     * NFC Tools. This is a dictionary attack over likely passwords, not an
     * exhaustive search; it is meant for recovering your own forgotten password.
     *
     * @param userGuesses the owner's own likely passwords (tried first)
     * @param wordlist    fallback common-password list
     */
    fun recoverNfcToolsPassword(
        tag: Tag,
        userGuesses: List<String>,
        wordlist: List<String>
    ): String {
        val sb = StringBuilder("NFC Tools password recovery (MD5[0..3] of text)\n")
        sb.append("UID: ").append(HexUtils.toHex(tag.id)).append('\n')

        val candidates = LinkedHashSet<String>()
        candidates.addAll(userGuesses)
        candidates.addAll(wordlist)
        if (candidates.isEmpty())
            return sb.append("No candidates. Type your likely passwords in the box.\n").toString()

        sb.append("Trying ").append(candidates.size).append(" password(s)...\n")
        var tried = 0
        var lost = 0
        for (text in candidates) {
            val pwd = NfcToolsPwd.derive(text)
            val pack = tryAuth(tag, pwd)
            tried++
            if (pack != null) {
                sb.append("SUCCESS after ").append(tried).append(" tries.\n")
                    .append("Password: \"").append(text).append("\"\n")
                    .append("PWD bytes: ").append(HexUtils.toHex(pwd))
                    .append("  PACK=").append(HexUtils.toHex(pack)).append('\n')
                    .append("Open NFC Tools -> remove password, enter this password.\n")
                return sb.toString()
            }
            // Detect the tag leaving the field so we don't report false "no match".
            if (!isTagPresent(tag)) {
                lost++
                if (lost >= 3) {
                    sb.append("Tag left the field after ").append(tried)
                        .append(" tries. Hold it still and run again to continue.\n")
                    return sb.toString()
                }
            } else {
                lost = 0
            }
        }
        sb.append("No match in ").append(tried).append(" candidates. ")
            .append("Add more of your own likely passwords to the box and retry.\n")
        return sb.toString()
    }

    private fun isTagPresent(tag: Tag): Boolean {
        val a = NfcA.get(tag) ?: return false
        return try { a.connect(); true } catch (e: Exception) { false }
        finally { closeQuietly(a) }
    }

    /** One PWD_AUTH attempt. Returns the 2-byte PACK on success, null on reject. */
    private fun tryAuth(tag: Tag, pwd: ByteArray): ByteArray? {
        val a = NfcA.get(tag) ?: return null
        return try {
            a.connect()
            a.timeout = 300
            val resp = a.transceive(
                byteArrayOf(CMD_PWD_AUTH, pwd[0], pwd[1], pwd[2], pwd[3])
            )
            if (resp != null && resp.size >= 2) resp.copyOf(2) else null
        } catch (e: Exception) {
            null // NAK / disconnect == wrong password
        } finally { closeQuietly(a) }
    }

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

    private fun readNdef(tag: Tag): String? {
        val ndef = Ndef.get(tag) ?: return null
        return try {
            ndef.connect()
            val msg = ndef.cachedNdefMessage ?: ndef.ndefMessage ?: return "empty"
            val sb = StringBuilder()
            for (r in msg.records) {
                sb.append("record tnf=").append(r.tnf)
                    .append(" type=").append(HexUtils.toAscii(r.type))
                    .append(" payload=").append(HexUtils.toAscii(r.payload))
                    .append('\n')
            }
            sb.toString()
        } catch (e: Exception) { "NDEF read error: ${e.message}" }
        finally { closeQuietly(ndef) }
    }

    private fun tryTransceive(a: NfcA, cmd: ByteArray): ByteArray? = try {
        a.transceive(cmd)
    } catch (e: IOException) { null } catch (e: Exception) { null }

    private fun guessPageCount(version: ByteArray?): Int {
        if (version != null && version.size >= 8) {
            // storage-size byte indicates the part family
            return when (version[6].toInt() and 0xFF) {
                0x0B -> 20   // MF0UL11 (48B user memory)
                0x0E -> 41   // MF0UL21 (128B user memory)
                0x0F -> 45   // NTAG213
                0x11 -> 135  // NTAG215
                0x13 -> 231  // NTAG216
                else -> 64
            }
        }
        return 64 // safe upper bound; readAllPages trims on first failed read
    }

    private fun decodeVersion(v: ByteArray): String {
        if (v.size < 8) return "unknown"
        val storage = v[6].toInt() and 0xFF
        return when (storage) {
            0x0B -> "MIFARE Ultralight EV1 (MF0UL11, 48B user)"
            0x0E -> "MIFARE Ultralight EV1 (MF0UL21, 128B user)"
            0x0F -> "NTAG213"
            0x11 -> "NTAG215"
            0x13 -> "NTAG216"
            else -> "NXP part, storage byte 0x%02X".format(storage)
        }
    }

    private fun ultralightTypeName(type: Int): String = when (type) {
        MifareUltralight.TYPE_ULTRALIGHT -> "Ultralight (classic)"
        MifareUltralight.TYPE_ULTRALIGHT_C -> "Ultralight C (3DES)"
        else -> "Ultralight (EV1/NTAG family)"
    }

    private fun closeQuietly(c: android.nfc.tech.TagTechnology?) {
        try { c?.close() } catch (_: Exception) {}
    }
}
