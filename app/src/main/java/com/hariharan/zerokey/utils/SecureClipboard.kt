package com.hariharan.zerokey.utils

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

/**
 * Copies sensitive text to the system clipboard with auto-clear and a flag that
 * tells Android (API 33+) the content is sensitive (so screen captures hide it).
 */
object SecureClipboard {

    /** Canonical label so any auto-clear logic can identify ZeroKey-copied content. */
    const val CLIP_LABEL = "ZeroKey_Secret"

    private const val CLEAR_AFTER_MS = 45_000L

    fun copy(context: Context, value: String) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(CLIP_LABEL, value)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
            clip.description.extras = extras
        }
        cm.setPrimaryClip(clip)

        Handler(Looper.getMainLooper()).postDelayed({
            try {
                val current = cm.primaryClip
                val stillOurs = current?.description?.label
                    ?.toString()
                    ?.equals(CLIP_LABEL, ignoreCase = true) == true
                if (stillOurs) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                        cm.clearPrimaryClip()
                    } else {
                        cm.setPrimaryClip(ClipData.newPlainText("", ""))
                    }
                }
            } catch (_: Exception) { /* best effort */ }
        }, CLEAR_AFTER_MS)
    }
}
