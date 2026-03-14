package com.hariharan.zerokey.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Requirement 7: Offline Privacy Mode.
 * Allows the user to disable all cloud synchronization and keep data local-only.
 */
class PrivacyModeManager(context: Context) {

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "privacy_mode_prefs",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_OFFLINE_ONLY = "offline_only_mode"
    }

    /**
     * Enables or disables local-only mode.
     */
    fun setOfflineOnly(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_OFFLINE_ONLY, enabled).apply()
    }

    /**
     * Returns true if cloud sync should be disabled.
     */
    fun isOfflineOnly(): Boolean {
        return prefs.getBoolean(KEY_OFFLINE_ONLY, false)
    }
}
