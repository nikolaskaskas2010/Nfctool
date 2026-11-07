package com.nfctool.app

import java.security.MessageDigest

/**
 * Password derivation used by the "NFC Tools" app (wakdev) when it protects an
 * NTAG21x / Ultralight EV1 tag:
 *
 *   PWD  = first 4 bytes of MD5(password_text)
 *
 * (The chip's PWD is only 4 bytes, so the app hashes the human-typed string and
 * keeps the leading 4 bytes.) Knowing this lets the OWNER of a tag recover a
 * FORGOTTEN password by trying a wordlist of their own likely passwords — the
 * normal "I forgot my own password" recovery, bounded by a human wordlist
 * rather than an exhaustive 2^32 search.
 */
object NfcToolsPwd {

    /** first 4 bytes of MD5(text) using UTF-8, matching NFC Tools. */
    fun derive(text: String): ByteArray {
        val md5 = MessageDigest.getInstance("MD5").digest(text.toByteArray(Charsets.UTF_8))
        return md5.copyOf(4)
    }

    /** Split a user's free-text guesses into candidate strings. */
    fun splitCandidates(raw: String): List<String> =
        raw.split('\n', ',', ';', ' ', '\t')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
            .distinct()
}
