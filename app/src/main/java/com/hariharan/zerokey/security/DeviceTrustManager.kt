package com.hariharan.zerokey.security

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.hariharan.zerokey.core.common.PrivacyLogger
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await

/**
 * Phase 11: Device Trust System.
 * Restricts vault sync to devices explicitly trusted by the user.
 */
class DeviceTrustManager(
    private val context: Context,
    private val firestore: FirebaseFirestore
) {

    private val COLLECTION_DEVICES = "devices"

    data class DeviceInfo(
        val deviceId: String,
        val deviceName: String,
        val lastSeen: Long,
        val isTrusted: Boolean
    )

    fun getCurrentDeviceId(): String {
        return Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
    }

    fun getDeviceName(): String {
        return "${Build.MANUFACTURER} ${Build.MODEL}"
    }

    /**
     * Registers the current device in the user's trusted list.
     * Requires biometric verification before calling this.
     */
    suspend fun registerCurrentDevice(userId: String) {
        val deviceId = getCurrentDeviceId()
        val deviceData = mapOf(
            "deviceId" to deviceId,
            "deviceName" to getDeviceName(),
            "lastSeen" to System.currentTimeMillis(),
            "trusted" to true,
            "revoked" to false
        )
        
        firestore.collection("users")
            .document(userId)
            .collection(COLLECTION_DEVICES)
            .document(deviceId)
            .set(deviceData)
            .await()
    }

    /**
     * Checks if the current device is trusted.
     */
    suspend fun isCurrentDeviceTrusted(userId: String): Boolean {
        val deviceId = getCurrentDeviceId()
        val doc = firestore.collection("users")
            .document(userId)
            .collection(COLLECTION_DEVICES)
            .document(deviceId)
            .get()
            .await()
            
        return doc.getBoolean("trusted") ?: false
    }

    /**
     * Returns true ONLY if this device has an explicit trust record set to false (revoked).
     * Missing record, offline, or any error -> false, so we never lock a user out by accident.
     */
    suspend fun isCurrentDeviceRevoked(userId: String): Boolean {
        return try {
            val deviceId = getCurrentDeviceId()
            val doc = firestore.collection("users")
                .document(userId)
                .collection(COLLECTION_DEVICES)
                .document(deviceId)
                .get()
                .await()
            doc.exists() && (doc.getBoolean("trusted") == false)
        } catch (e: Exception) {
            PrivacyLogger.e("DeviceTrustManager", "Trust check failed (offline?). Not locking.")
            false
        }
    }

    /**
     * Revokes trust from a specific device.
     */
    suspend fun revokeDeviceTrust(userId: String, deviceId: String) {
        firestore.collection("users")
            .document(userId)
            .collection(COLLECTION_DEVICES)
            .document(deviceId)
            .update(mapOf("trusted" to false, "revoked" to true))
            .await()
    }

    /**
     * Fetches all registered devices for the user.
     */
    suspend fun getTrustedDevices(userId: String): List<DeviceInfo> {
        val snapshot = firestore.collection("users")
            .document(userId)
            .collection(COLLECTION_DEVICES)
            .get()
            .await()
            
        return snapshot.documents.map { doc ->
            DeviceInfo(
                deviceId = doc.id,
                deviceName = doc.getString("deviceName") ?: "Unknown Device",
                lastSeen = doc.getLong("lastSeen") ?: 0L,
                isTrusted = doc.getBoolean("trusted") ?: false
            )
        }
    }
}
