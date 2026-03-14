package com.hariharan.zerokey.security

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * Phase 12: Emergency Access Manager.
 * Implements a 48-hour delay for trusted contact access.
 */
class EmergencyAccessManager(context: Context) {

    private val prefs = EncryptedSharedPreferences.create(
        context,
        "emergency_access_prefs",
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    companion object {
        private const val KEY_CONTACT_ID = "emergency_contact_id"
        private const val KEY_REQUEST_TIME = "access_request_timestamp"
        private const val ACCESS_DELAY_MS = 48 * 60 * 60 * 1000L // 48 Hours
    }

    /**
     * Set the trusted contact's ID (e.g., their Firebase UID).
     */
    fun setEmergencyContact(uid: String) {
        prefs.edit().putString(KEY_CONTACT_ID, uid).apply()
    }

    /**
     * Starts the 48-hour countdown.
     */
    fun initiateAccessRequest(uid: String) {
        val storedUid = prefs.getString(KEY_CONTACT_ID, null)
        if (storedUid != null && storedUid == uid) {
            prefs.edit().putLong(KEY_REQUEST_TIME, System.currentTimeMillis()).apply()
        }
    }

    /**
     * Allows the user to cancel any pending request.
     */
    fun cancelRequest() {
        prefs.edit().remove(KEY_REQUEST_TIME).apply()
    }

    /**
     * Checks if the 48-hour period has elapsed.
     */
    fun isAccessGranted(): Boolean {
        val requestTime = prefs.getLong(KEY_REQUEST_TIME, 0)
        if (requestTime == 0L) return false
        
        return (System.currentTimeMillis() - requestTime) >= ACCESS_DELAY_MS
    }

    fun getRemainingTime(): Long {
        val requestTime = prefs.getLong(KEY_REQUEST_TIME, 0)
        if (requestTime == 0L) return 0
        val elapsed = System.currentTimeMillis() - requestTime
        return (ACCESS_DELAY_MS - elapsed).coerceAtLeast(0)
    }
}
