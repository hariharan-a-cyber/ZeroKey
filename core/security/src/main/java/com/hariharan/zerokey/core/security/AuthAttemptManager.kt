package com.hariharan.zerokey.core.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Requirement 10: Brute-force protection with exponential backoff.
 */
@Singleton
class AuthAttemptManager @Inject constructor(@ApplicationContext private val context: Context) {

    private val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

    private val prefs = EncryptedSharedPreferences.create(
        "auth_attempts_prefs",
        masterKeyAlias,
        context,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_TIME = "lockout_time"
    }

    fun recordFailedAttempt(userId: String = "unknown") {
        val attempts = getFailedAttempts() + 1
        prefs.edit().putInt(KEY_ATTEMPTS, attempts).apply()
        
        // Security Logging: Track user, device, and time.
        val deviceId = android.provider.Settings.Secure.getString(context.contentResolver, android.provider.Settings.Secure.ANDROID_ID)
        com.hariharan.zerokey.core.common.PrivacyLogger.e("SecurityAuth", "BRUTE_FORCE_ALERT: Failed attempt for $userId on device $deviceId. Attempt #$attempts")

        val lockoutDuration = calculateLockoutDuration(attempts)
        if (lockoutDuration > 0) {
            prefs.edit().putLong(KEY_LOCKOUT_TIME, System.currentTimeMillis() + lockoutDuration).apply()
        }
    }

    private fun calculateLockoutDuration(attempts: Int): Long {
        return when (attempts) {
            1, 2, 3, 4, 5 -> 0L // No timeout for first 5 attempts
            6 -> 30_000L      // 30s (Changed from 30m)
            8 -> 120_000L     // 2m
            9 -> 300_000L     // 5m
            10 -> 900_000L    // 15m
            else -> if (attempts > 10) 900_000L else 0L
        }
    }

    fun needsCaptcha(): Boolean {
        // Since first 5 are free, captcha now follows at 7-9 as before, or adjusted if needed.
        // Keeping it at 7-9 as per original plan unless user specifies otherwise.
        return getFailedAttempts() in 7..9
    }

    fun isHardLocked(): Boolean {
        return getFailedAttempts() >= 10
    }

    fun resetAttempts() {
        prefs.edit().putInt(KEY_ATTEMPTS, 0).remove(KEY_LOCKOUT_TIME).apply()
    }

    fun isLockedOut(): Boolean {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_TIME, 0)
        if (lockoutUntil == 0L) return false
        
        return System.currentTimeMillis() < lockoutUntil
    }

    fun getFailedAttempts(): Int = prefs.getInt(KEY_ATTEMPTS, 0)
    
    fun getRemainingLockoutTime(): Long {
        val lockoutUntil = prefs.getLong(KEY_LOCKOUT_TIME, 0)
        if (lockoutUntil == 0L) return 0
        return (lockoutUntil - System.currentTimeMillis()).coerceAtLeast(0)
    }
}
