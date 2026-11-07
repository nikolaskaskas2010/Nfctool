# NFC Tool (Android)

A practical NFC/RFID utility for Android that reads, writes, formats, clears and
dumps the raw memory of common NFC tags — with first-class support for **NfcA**,
**MIFARE Ultralight / Ultralight EV1**, and **NdefFormatable** tags.

> Use this only on tags you own or are explicitly authorized to test.

## Features

| Operation | What it does |
|-----------|--------------|
| **Read / Dump** | Reads UID, ATQA/SAK, `GET_VERSION`, then dumps every readable page as annotated hex + ASCII, and decodes the headers (BCC, CC, lock bytes, EV1 config). |
| **Write NDEF** | Writes a Text or URI record. Auto-formats `NdefFormatable` tags. |
| **Format NDEF** | Turns a blank `NdefFormatable` tag into an empty NDEF tag. |
| **Clear / Erase** | Zeroes the user-data pages (page 4 → last user page), leaving UID/CC/config intact. |
| **Recover Password** | Tries documented **default** `PWD_AUTH` passwords (+ one optional manual candidate) to regain access to a tag left on defaults. |
| **Make Read-Only** | Sets NDEF lock bits. **Permanent and irreversible** — asked for explicitly. |

Supported tech, via `enableReaderMode`: `NfcA`, `NfcB`, `NfcF`, `NfcV`,
`MifareUltralight`, `Ndef`, `NdefFormatable`, `IsoDep`, `MifareClassic`
(the UI operations are tuned for the Ultralight/NTAG family).

## Honest notes on "cracking" and locks

NFC tags use several different "locks". They are not equivalent, and only one of
them is ever recoverable:

- **Static / dynamic lock bytes & OTP bits** (what makes a page "read-only"):
  these are one-time-programmable hardware fuses. Once set they are *physically
  permanent*. No app, phone or reader can clear them. This tool **shows** their
  state; nothing can revert them.
- **Password protection** (`PWD_AUTH` on Ultralight EV1 / NTAG21x; 3DES on
  Ultralight-C): recoverable **only** when the tag still uses a known/default
  password. The 32-bit password space is far too large to brute-force on a phone
  in practical time, so this tool ships a short *default-password* list, not an
  exhaustive cracker. A tag with a genuine custom password will not be recovered.
- **Encrypted payloads**: many deployed tags store an encrypted/encoded blob.
  Reading the bytes (which may be freely allowed) does not reveal the plaintext,
  and copying bytes does not necessarily reproduce the tag's function.

## Build

Requires the Android SDK (platform 35, build-tools 35.0.0). Easiest path is
Android Studio: **Open** this folder and press **Run**, or from the CLI:

```bash
# point the build at your SDK
echo "sdk.dir=/path/to/Android/sdk" > local.properties

./gradlew :app:assembleDebug        # debug APK
# -> app/build/outputs/apk/debug/app-debug.apk
```

Install with `adb install -r app/build/outputs/apk/debug/app-debug.apk`.

## Usage

1. Launch the app (NFC must be enabled in system settings).
2. Tap an operation button to arm it (for **Write** / **Recover**, type into the
   input field first — text/URL to write, or a 4-byte hex password to try).
3. Hold a tag to the back of the phone. Results stream into the log, which is
   selectable so you can copy a dump out.

## Project layout

```
app/src/main/java/com/nfctool/app/
  MainActivity.kt        UI + NFC reader-mode dispatch
  NfcEngine.kt           read/dump/write/format/clear/makeReadOnly/recover
  TagAnalyzer.kt         decodes UID/BCC/CC/lock bytes/EV1 config
  PasswordDictionary.kt  documented default PWD_AUTH values
  HexUtils.kt            hex/ascii/page-dump helpers
```
