package com.hariharan.zerokey.core.common

import android.util.Log
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Privacy-Aware Logger for ZeroKey.
 * Ensures that sensitive metadata like domains, package names, and UIDs 
 * are masked before being written to system logs or crash reports.
 * 
 * Uses HMAC-SHA256 with a rotating diagnostic key to prevent long-term correlation.
 * Hardened to sanitize PII like Emails, IP Addresses, and UIDs recursively.
 */
object PrivacyLogger {

    private const val GLOBAL_TAG = "ZeroKey_Safe"
    private const val ALGORITHM = "HmacSHA256"
    private const val ROTATION_INTERVAL_MS = 24 * 60 * 60 * 1000L // 24 Hours

    @Volatile
    private var diagnosticKey: ByteArray = generateKey()
    @Volatile
    private var lastRotationTime: Long = System.currentTimeMillis()

    private fun generateKey(): ByteArray {
        val key = ByteArray(32)
        SecureRandom().nextBytes(key)
        return key
    }

    @Synchronized
    private fun getDiagnosticKey(): ByteArray {
        val now = System.currentTimeMillis()
        if ((now - lastRotationTime) > ROTATION_INTERVAL_MS) {
            diagnosticKey = generateKey()
            lastRotationTime = now
        }
        return diagnosticKey
    }

    fun v(tag: String, msg: String) = Log.v(GLOBAL_TAG, "[$tag] ${sanitizeError(msg)}")
    fun d(tag: String, msg: String) = Log.d(GLOBAL_TAG, "[$tag] ${sanitizeError(msg)}")
    fun i(tag: String, msg: String) = Log.i(GLOBAL_TAG, "[$tag] ${sanitizeError(msg)}")
    fun w(tag: String, msg: String) = Log.w(GLOBAL_TAG, "[$tag] ${sanitizeError(msg)}")
    fun w(tag: String, msg: String, tr: Throwable) = Log.w(GLOBAL_TAG, "[$tag] ${sanitizeError(msg)}", sanitizeThrowable(tr))
    fun e(tag: String, msg: String, tr: Throwable? = null) = Log.e(GLOBAL_TAG, "[$tag] ${sanitizeError(msg)}", tr?.let { sanitizeThrowable(it) })

    /**
     * Masks a sensitive string (domain, package, etc) with a keyed HMAC.
     * The hash is stable for 24 hours but rotates to prevent long-term tracking.
     */
    fun mask(value: String?): String {
        if (value == null) return "null"
        if (value.isBlank()) return "empty"
        
        return try {
            val mac = Mac.getInstance(ALGORITHM)
            mac.init(SecretKeySpec(getDiagnosticKey(), ALGORITHM))
            val hash = mac.doFinal(value.toByteArray())
            val hexHash = hash.asSequence().take(4).joinToString("") { "%02x".format(it) }
            "hash:$hexHash..."
        } catch (ignored: Exception) {
            "masked_err"
        }
    }

    /**
     * Sanitize a message to remove potentially sensitive data (Emails, IPs, IDs).
     */
    fun sanitizeError(msg: String?): String {
        if (msg == null) return "null"
        return msg.replace(Regex("[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}"), "masked_domain")
                  .replace(Regex("/[a-zA-Z0-9._/-]+"), "/masked_path")
                  .replace(Regex("[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]+"), "masked_email")
                  .replace(Regex("\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b"), "masked_ip")
                  .replace(Regex("\\b[a-zA-Z0-9]{20,}\\b"), "masked_id") // Potential UIDs or Tokens
    }

    /**
     * Recursively sanitize a Throwable's message while preserving the stack trace.
     */
    private fun sanitizeThrowable(tr: Throwable): Throwable {
        val sanitizedMessage = sanitizeError(tr.message)
        val cause = tr.cause?.let { sanitizeThrowable(it) }
        
        return object : Throwable(sanitizedMessage, cause) {
            override fun getStackTrace(): Array<StackTraceElement> = tr.stackTrace
            override fun fillInStackTrace(): Throwable = this // Avoid re-filling
            override fun toString(): String {
                val s = javaClass.name
                val message = localizedMessage
                return if (message != null) "$s: $message" else s
            }
        }
    }
}
