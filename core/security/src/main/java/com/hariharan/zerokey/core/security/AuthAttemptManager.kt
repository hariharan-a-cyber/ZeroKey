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

    private fun getPrefs(userId: String): android.content.SharedPreferences {
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val safeId = android.util.Base64.encodeToString(userId.toByteArray(), android.util.Base64.NO_WRAP)
        return EncryptedSharedPreferences.create(
            "auth_attempts_prefs_$safeId",
            masterKeyAlias,
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    companion object {
        private const val KEY_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_TIME = "lockout_time"
        private const val KEY_LAST_ATTEMPT_TIME = "last_attempt_time"
        private const val ATTEMPT_EXPIRATION_TIME_MS = 30 * 60 * 1000L // 30 minutes
    }

    fun recordFailedAttempt(userId: String = "unknown") {
        val prefs = getPrefs(userId)
        val now = System.currentTimeMillis()
        val lastAttempt = prefs.getLong(KEY_LAST_ATTEMPT_TIME, 0)
        
        var attempts = getFailedAttempts(userId)
        
        // If more than 30 mins passed since last failure, reset the "streak"
        if (lastAttempt != 0L && (now - lastAttempt > ATTEMPT_EXPIRATION_TIME_MS)) {
            attempts = 1
        } else {
            attempts += 1
        }

        prefs.edit()
            .putInt(KEY_ATTEMPTS, attempts)
            .putLong(KEY_LAST_ATTEMPT_TIME, now)
            .apply()
        
        // Security Logging: Track masked user and device.
        val deviceId = android.provider.Settings.Secure.getString(context.contentResolver, android.provider.Settings.Secure.ANDROID_ID)
        com.hariharan.zerokey.core.common.PrivacyLogger.e("SecurityAuth", "BRUTE_FORCE_ALERT: attempt #$attempts for ${com.hariharan.zerokey.core.common.PrivacyLogger.mask(userId)} on ${com.hariharan.zerokey.core.common.PrivacyLogger.mask(deviceId)}")

        val lockoutDuration = calculateLockoutDuration(attempts)
        if (lockoutDuration > 0) {
            prefs.edit().putLong(KEY_LOCKOUT_TIME, System.currentTimeMillis() + lockoutDuration).apply()
        }
    }

    private fun calculateLockoutDuration(attempts: Int): Long {
        return when (attempts) {
            in 1..3 -> 0L       // 3 free
            4 -> 15_000L        // 15s
            5 -> 60_000L        // 1m
            6 -> 300_000L       // 5m
            7 -> 900_000L       // 15m
            8 -> 3600_000L      // 1h
            9 -> 14400_000L     // 4h
            10 -> 86400_000L    // 24h
            else -> 7L * 24 * 60 * 60 * 1000 // 7 days
        }
    }

    fun resetAttempts(userId: String = "unknown") {
        getPrefs(userId).edit()
            .putInt(KEY_ATTEMPTS, 0)
            .remove(KEY_LOCKOUT_TIME)
            .remove(KEY_LAST_ATTEMPT_TIME)
            .apply()
    }

    fun isLockedOut(userId: String = "unknown"): Boolean {
        val lockoutUntil = getPrefs(userId).getLong(KEY_LOCKOUT_TIME, 0)
        if (lockoutUntil == 0L) return false
        
        return System.currentTimeMillis() < lockoutUntil
    }

    fun getFailedAttempts(userId: String = "unknown"): Int {
        val prefs = getPrefs(userId)
        val attempts = prefs.getInt(KEY_ATTEMPTS, 0)
        if (attempts == 0) return 0

        val lastAttempt = prefs.getLong(KEY_LAST_ATTEMPT_TIME, 0)
        val now = System.currentTimeMillis()

        // If the last attempt expired, treat current count as 0
        if (lastAttempt != 0L && (now - lastAttempt > ATTEMPT_EXPIRATION_TIME_MS)) {
            return 0
        }
        return attempts
    }
    
    fun getRemainingLockoutTime(userId: String = "unknown"): Long {
        val lockoutUntil = getPrefs(userId).getLong(KEY_LOCKOUT_TIME, 0)
        if (lockoutUntil == 0L) return 0
        return (lockoutUntil - System.currentTimeMillis()).coerceAtLeast(0)
    }
}
