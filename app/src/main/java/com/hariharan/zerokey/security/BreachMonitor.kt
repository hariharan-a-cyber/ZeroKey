package com.hariharan.zerokey.security

import android.util.Log
import io.ktor.client.*
import io.ktor.client.engine.android.*
import io.ktor.client.plugins.logging.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import java.security.MessageDigest

/**
 * Privacy-preserving Breach Monitor using the k-anonymity model.
 * Network queries use SHA-1 prefixes to prevent exposing the full password.
 */
object BreachMonitor {

    private val client = HttpClient(Android) {
        install(Logging) {
            level = LogLevel.INFO
        }
    }

    /**
     * Converts a password into a SHA-1 hash.
     */
    fun hashPassword(password: String): String {
        val bytes = MessageDigest.getInstance("SHA-1").digest(password.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }.uppercase()
    }

    /**
     * Queries the Have I Been Pwned API using the 5-character prefix.
     * Returns true if the password hash suffix is found in the results.
     */
    suspend fun checkBreach(password: String): Boolean {
        if (password.isBlank()) return false
        
        try {
            val fullHash = hashPassword(password)
            val prefix = fullHash.take(5)
            val suffix = fullHash.substring(5)

            val response: HttpResponse = client.get("https://api.pwnedpasswords.com/range/$prefix")
            
            if (response.status.value == 200) {
                val body = response.bodyAsText()
                val found = body.lineSequence().any { line ->
                    line.split(":")[0] == suffix
                }
                if (found) {
                    Log.w("BreachMonitor", "Password breach detected for hash prefix $prefix")
                }
                return found
            }
        } catch (e: Exception) {
            Log.e("BreachMonitor", "Failed to check password breach", e)
        }
        return false
    }
}
