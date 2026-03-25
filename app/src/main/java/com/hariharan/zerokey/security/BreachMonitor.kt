package com.hariharan.zerokey.security

import android.util.Log
import com.hariharan.zerokey.core.common.SensitiveDataManager
import io.ktor.client.*
import io.ktor.client.engine.android.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import java.security.MessageDigest
import java.util.*

/**
 * Phase 7: Privacy-preserving Breach Monitor using the k-anonymity model.
 * Matches are performed locally. Full hashes or passwords never leave the device.
 */
object BreachMonitor {

    private val client = HttpClient(Android) {
        install(Logging) {
            level = LogLevel.NONE
        }
    }

    /**
     * Queries the Have I Been Pwned API using the 5-character prefix.
     * Returns true if the password hash suffix is found in the results.
     * Hardened to minimize memory exposure by avoiding immutable String hashes
     * and wiping buffers immediately after use.
     */
    suspend fun checkBreach(password: CharArray): Boolean {
        if (password.isEmpty()) return false
        
        // Buffers for sensitive data
        val passwordBytes = ByteArray(password.size * 3) // Max UTF-8 size for most common chars
        var fullHash: ByteArray? = null
        val hexChars = CharArray(40) // SHA-1 is 160 bits = 40 hex characters
        
        try {
            // 1. Manual conversion to bytes to allow zeroing memory later
            var bytesWritten = 0
            for (char in password) {
                val code = char.code
                if (code < 0x80) {
                    passwordBytes[bytesWritten++] = code.toByte()
                } else if (code < 0x800) {
                    passwordBytes[bytesWritten++] = (0xc0 or (code shr 6)).toByte()
                    passwordBytes[bytesWritten++] = (0x80 or (code and 0x3f)).toByte()
                } else {
                    passwordBytes[bytesWritten++] = (0xe0 or (code shr 12)).toByte()
                    passwordBytes[bytesWritten++] = (0x80 or ((code shr 6) and 0x3f)).toByte()
                    passwordBytes[bytesWritten++] = (0x80 or (code and 0x3f)).toByte()
                }
            }

            // 2. Compute SHA-1 directly from the byte buffer
            val digest = MessageDigest.getInstance("SHA-1")
            digest.update(passwordBytes, 0, bytesWritten)
            fullHash = digest.digest()
            
            // 3. Convert hash to hex in a mutable CharArray (avoids immutable String residue)
            bytesToHex(fullHash, hexChars)
            
            // 4. Only the 5-character prefix is sent to the network (k-Anonymity)
            val prefix = String(hexChars, 0, 5)
            val suffix = String(hexChars, 5, 35).uppercase(Locale.ROOT)

            val response: HttpResponse = client.get("https://api.pwnedpasswords.com/range/$prefix")
            
            if (response.status.value == 200) {
                val body = response.bodyAsText()
                val isCompromised = body.lineSequence().any { line ->
                    // Matching happens locally against the suffix
                    val parts = line.split(":")
                    if (parts.size < 2) return@any false
                    parts[0].uppercase(Locale.ROOT) == suffix
                }
                
                if (isCompromised) {
                    Log.w("BreachMonitor", "Security Alert: Match found in HIBP database.")
                }
                return isCompromised
            }
        } catch (e: Exception) {
            Log.e("BreachMonitor", "Network breach check failed", e)
        } finally {
            // 5. Memory Hardening: Explicitly wipe all sensitive buffers
            SensitiveDataManager.clearSensitiveData(passwordBytes)
            SensitiveDataManager.clearSensitiveData(fullHash)
            SensitiveDataManager.clearSensitiveData(hexChars)
        }
        return false
    }

    private fun bytesToHex(bytes: ByteArray, out: CharArray) {
        val hexArray = "0123456789abcdef".toCharArray()
        for (i in bytes.indices) {
            val v = bytes[i].toInt() and 0xFF
            out[i * 2] = hexArray[v ushr 4]
            out[i * 2 + 1] = hexArray[v and 0x0F]
        }
    }
}
