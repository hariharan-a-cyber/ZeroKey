package com.hariharan.zerokey.core.security

import com.hariharan.zerokey.core.common.PrivacyLogger
import com.hariharan.zerokey.core.common.SensitiveDataManager
import io.ktor.client.*
import io.ktor.client.engine.android.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import java.security.MessageDigest
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.util.*
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Phase 7: Privacy-preserving Breach Monitor using the k-anonymity model.
 * Matches are performed locally. Full hashes or passwords never leave the device.
 */
@Singleton
class BreachMonitor @Inject constructor() {

    private val client = HttpClient(Android) {
        install(Logging) {
            level = LogLevel.NONE
        }
    }

    /**
     * Queries the Have I Been Pwned API using the 5-character prefix.
     * Returns true if the password hash suffix is found in the results.
     * Hardened to minimize memory exposure by avoiding immutable String hashes.
     */
    suspend fun checkBreach(password: CharArray): Boolean {
        if (password.isEmpty()) return false
        
        var passwordBytes: ByteArray? = null
        var fullHash: ByteArray? = null
        val hexChars = CharArray(40)

        try {
            // Correct UTF-8 encoding (handles emoji / surrogate pairs) without an intermediate String.
            val encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password))
            passwordBytes = ByteArray(encoded.remaining())
            encoded.get(passwordBytes)

            val digest = MessageDigest.getInstance("SHA-1")
            digest.update(passwordBytes)
            fullHash = digest.digest()
            
            bytesToHex(fullHash, hexChars)
            
            val prefix = String(hexChars, 0, 5)
            val suffix = String(hexChars, 5, 35).uppercase(Locale.ROOT)

            val response: HttpResponse = client.get("https://api.pwnedpasswords.com/range/$prefix")
            
            if (response.status.value == 200) {
                val body = response.bodyAsText()
                val isCompromised = body.lineSequence().any { line ->
                    val parts = line.split(":")
                    if (parts.size < 2) return@any false
                    parts[0].uppercase(Locale.ROOT) == suffix
                }
                
                if (isCompromised) {
                    PrivacyLogger.w("BreachMonitor", "Security Alert: Match found in HIBP database.")
                }
                return isCompromised
            }
        } catch (e: Exception) {
            PrivacyLogger.e("BreachMonitor", "Network breach check failed", e)
        } finally {
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
