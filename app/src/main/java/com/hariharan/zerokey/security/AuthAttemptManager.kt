package com.hariharan.zerokey.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Requirement 10: Brute-force protection with exponential backoff.
 */
class AuthAttemptManager(context: Context) {

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "auth_attempts_prefs",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_TIME = "lockout_time"
        private const val MAX_FREE_ATTEMPTS = 5
    }

    fun recordFailedAttempt() {
        val attempts = getFailedAttempts() + 1
        prefs.edit().putInt(KEY_ATTEMPTS, attempts).apply()
        
        if (attempts >= MAX_FREE_ATTEMPTS) {
            val lockoutDuration = calculateLockoutDuration(attempts)
            prefs.edit().putLong(KEY_LOCKOUT_TIME, System.currentTimeMillis() + lockoutDuration).apply()
        }
    }

    private fun calculateLockoutDuration(attempts: Int): Long {
        return when (attempts) {
            5 -> 30_000L      // 30s
            6 -> 60_000L      // 60s
            7 -> 120_000L     // 120s
            else -> 300_000L  // 300s (Max)
        }
    }

    fun resetAttempts() {
        prefs.edit().putInt(KEY_ATTEMPTS, 0).remove(KEY_LOCKOUT_TIME).apply()
    }

    fun isLockedOut(): Boolean {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_TIME, 0)
        if (lockoutUntil == 0L) return false
        
        val isLocked = System.currentTimeMillis() < lockoutUntil
        if (!isLocked) {
            // Lockout period expired
            return false
        }
        return true
    }

    fun getFailedAttempts(): Int = prefs.getInt(KEY_ATTEMPTS, 0)
    
    fun getRemainingLockoutTime(): Long {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_TIME, 0)
        if (lockoutUntil == 0L) return 0
        return (lockoutUntil - System.currentTimeMillis()).coerceAtLeast(0)
    }
}
