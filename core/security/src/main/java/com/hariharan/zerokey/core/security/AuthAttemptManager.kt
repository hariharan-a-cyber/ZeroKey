package com.hariharan.zerokey.core.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.hariharan.zerokey.core.common.PrivacyLogger
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AuthAttemptManager @Inject constructor(
    @ApplicationContext private val context: Context
) {
    companion object {
        private const val PREFS_NAME = "auth_attempts_prefs"
        private const val KEY_FAILED_COUNT = "failed_count"
        private const val KEY_LAST_FAILED_AT = "last_failed_at"
        private const val KEY_LOCKED_UNTIL = "locked_until"
    }

    private val prefs by lazy {
        EncryptedSharedPreferences.create(
            PREFS_NAME,
            MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC),
            context,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }

    /**
     * Doubling backoff with no ceiling. The 3 free attempts are kept for genuine
     * typos; after that, the cost rises sharply: 15s, 1m, 5m, 15m, 1h, 4h, 24h,
     * and 7 days for every attempt beyond.
     */
    private fun calculateLockoutDuration(attempts: Int): Long {
        return when {
            attempts <= 3 -> 0L
            attempts == 4 -> 15_000L
            attempts == 5 -> 60_000L
            attempts == 6 -> 5 * 60_000L
            attempts == 7 -> 15 * 60_000L
            attempts == 8 -> 60 * 60_000L
            attempts == 9 -> 4 * 60 * 60_000L
            attempts == 10 -> 24 * 60 * 60_000L
            else -> 7L * 24 * 60 * 60_000L
        }
    }

    fun recordFailedAttempt(context: String = ""): Long {
        val count = prefs.getInt(KEY_FAILED_COUNT, 0) + 1
        val now = System.currentTimeMillis()
        val lockoutMs = calculateLockoutDuration(count)
        val lockedUntil = if (lockoutMs > 0) now + lockoutMs else 0L

        prefs.edit()
            .putInt(KEY_FAILED_COUNT, count)
            .putLong(KEY_LAST_FAILED_AT, now)
            .putLong(KEY_LOCKED_UNTIL, lockedUntil)
            .apply()

        PrivacyLogger.w("AuthAttemptManager", "Failed attempt #$count (ctx=$context), lockout=${lockoutMs}ms")
        return lockoutMs
    }

    fun resetAttempts() {
        prefs.edit()
            .remove(KEY_FAILED_COUNT)
            .remove(KEY_LAST_FAILED_AT)
            .remove(KEY_LOCKED_UNTIL)
            .apply()
    }

    fun isLockedOut(): Boolean = getRemainingLockoutTime() > 0

    fun getRemainingLockoutTime(): Long {
        val until = prefs.getLong(KEY_LOCKED_UNTIL, 0L)
        val now = System.currentTimeMillis()
        return if (until > now) until - now else 0L
    }

    fun getCurrentAttemptCount(): Int = prefs.getInt(KEY_FAILED_COUNT, 0)
}
