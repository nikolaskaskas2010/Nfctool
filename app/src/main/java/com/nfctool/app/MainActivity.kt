package com.nfctool.app

import android.app.PendingIntent
import android.content.Intent
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.nfctool.app.databinding.ActivityMainBinding
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private lateinit var binding: ActivityMainBinding
    private var nfcAdapter: NfcAdapter? = null
    private val engine = NfcEngine()

    private enum class Op { READ, WRITE, FORMAT, CLEAR, RECOVER, NFCTOOLS, MAKE_RO }
    @Volatile private var currentOp: Op = Op.READ

    /** Bundled fallback wordlist, loaded once from res/raw. */
    private val commonWords: List<String> by lazy { loadWordlist() }

    private val readerFlags =
        NfcAdapter.FLAG_READER_NFC_A or
        NfcAdapter.FLAG_READER_NFC_B or
        NfcAdapter.FLAG_READER_NFC_F or
        NfcAdapter.FLAG_READER_NFC_V or
        NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS or
        NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null) {
            log("This device has no NFC hardware.")
            binding.statusText.text = "No NFC on this device."
        } else if (nfcAdapter?.isEnabled == false) {
            log("NFC is OFF. Enable it in system settings, then return here.")
        }

        binding.btnRead.setOnClickListener { select(Op.READ, "READ / DUMP") }
        binding.btnWrite.setOnClickListener { select(Op.WRITE, "WRITE NDEF") }
        binding.btnFormat.setOnClickListener { select(Op.FORMAT, "FORMAT") }
        binding.btnClear.setOnClickListener { select(Op.CLEAR, "CLEAR / ERASE") }
        binding.btnRecover.setOnClickListener { select(Op.RECOVER, "RECOVER PASSWORD") }
        binding.btnNfcTools.setOnClickListener {
            select(Op.NFCTOOLS, "NFC TOOLS PW (type your guesses in the box)")
        }
        binding.btnMakeRo.setOnClickListener {
            select(Op.MAKE_RO, "MAKE READ-ONLY (PERMANENT!)")
        }
        binding.btnClearLog.setOnClickListener { binding.logText.text = "" }
    }

    private fun select(op: Op, label: String) {
        currentOp = op
        binding.statusText.text = "Mode: $label — now tap a tag."
        Toast.makeText(this, label, Toast.LENGTH_SHORT).show()
    }

    override fun onResume() {
        super.onResume()
        // Reader mode gives us low-level transceive access and avoids the OS
        // trying to auto-handle the tag.
        nfcAdapter?.enableReaderMode(this, this, readerFlags, null)
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    /** Called on a background thread when a tag enters the field. */
    override fun onTagDiscovered(tag: Tag) {
        val op = currentOp
        val result = try {
            when (op) {
                Op.READ -> engine.dump(tag)
                Op.WRITE -> engine.writeNdef(tag, uiText())
                Op.FORMAT -> engine.format(tag)
                Op.CLEAR -> engine.clear(tag)
                Op.RECOVER -> engine.recoverPassword(tag, HexUtils.parseHex(uiText()))
                Op.NFCTOOLS -> engine.recoverNfcToolsPassword(
                    tag, NfcToolsPwd.splitCandidates(uiText()), commonWords
                )
                Op.MAKE_RO -> engine.makeReadOnly(tag)
            }
        } catch (e: Exception) {
            "Operation failed: ${e.message}"
        }
        runOnUiThread { log("[$op]\n$result") }
    }

    private fun uiText(): String = binding.writeInput.text?.toString()?.trim().orEmpty()

    private fun loadWordlist(): List<String> = try {
        resources.openRawResource(R.raw.common_passwords).bufferedReader().useLines { lines ->
            lines.map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
                .toList()
        }
    } catch (e: Exception) { emptyList() }

    private fun log(msg: String) {
        val ts = SimpleDateFormat("HH:mm:ss", Locale.US).format(Date())
        binding.logText.append("── $ts ──\n$msg\n\n")
        binding.logScroll.post {
            binding.logScroll.fullScroll(android.view.View.FOCUS_DOWN)
        }
    }

    // Also handle a tag delivered via the manifest TECH_DISCOVERED intent.
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        val tag: Tag? = if (Build.VERSION.SDK_INT >= 33)
            intent.getParcelableExtra(NfcAdapter.EXTRA_TAG, Tag::class.java)
        else @Suppress("DEPRECATION") intent.getParcelableExtra(NfcAdapter.EXTRA_TAG)
        tag?.let { onTagDiscovered(it) }
    }

    @Suppress("unused")
    private fun pendingIntentCompat(): PendingIntent {
        val flag = if (Build.VERSION.SDK_INT >= 31)
            PendingIntent.FLAG_MUTABLE else 0
        return PendingIntent.getActivity(
            this, 0,
            Intent(this, javaClass).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            flag
        )
    }
}
