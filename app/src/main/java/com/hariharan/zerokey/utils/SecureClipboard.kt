package com.hariharan.zerokey.utils

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle

object SecureClipboard {

    /** Copies sensitive text: flagged sensitive (API 33+) and auto-cleared after [clearAfterMs]. */
    fun copy(context: Context, label: String, secret: String, clearAfterMs: Long = 45_000L) {
        val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText(label, secret)
        if (Build.VERSION.SDK_INT >= 33) {
            clip.description.extras = PersistableBundle().apply {
                putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
            }
        } else {
            clip.description.extras = PersistableBundle().apply {
                putBoolean("android.content.extra.IS_SENSITIVE", true)
            }
        }
        cm.setPrimaryClip(clip)

        Handler(Looper.getMainLooper()).postDelayed({
            try {
                val current = cm.primaryClip?.getItemAt(0)?.text?.toString()
                if (current == secret) {
                    if (Build.VERSION.SDK_INT >= 28) cm.clearPrimaryClip()
                    else cm.setPrimaryClip(ClipData.newPlainText("", ""))
                }
            } catch (_: Exception) {}
        }, clearAfterMs)
    }
}
