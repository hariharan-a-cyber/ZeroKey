package com.hariharan.zerokey.security

import android.content.Context
import android.os.Build
import android.provider.Settings
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.core.common.PrivacyLogger
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.tasks.await
import javax.inject.Inject
import javax.inject.Singleton

data class DeviceInfo(
    val deviceId: String,
    val deviceName: String,
    val isTrusted: Boolean,
    val lastSeen: Long
)

@Singleton
class DeviceTrustManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val firestore: FirebaseFirestore
) {
    private val deviceId: String = Settings.Secure.getString(
        context.contentResolver,
        Settings.Secure.ANDROID_ID
    ) ?: "unknown_device"

    private val deviceName: String = "${Build.MANUFACTURER} ${Build.MODEL}"

    companion object {
        // If we haven't been able to confirm trust within this window, treat the
        // device as suspect. Long enough to survive normal outages, short enough
        // to limit attacker-controlled network throttling attacks.
        private const val TRUST_FRESHNESS_TTL_MS = 24L * 60 * 60 * 1000  // 24h
    }

    private val prefs by lazy {
        context.getSharedPreferences("zk_device_trust", Context.MODE_PRIVATE)
    }
    private fun lastSuccessfulCheckKey(userId: String) = "last_trust_check_${userId}"

    fun getDeviceId(): String = deviceId

    suspend fun getTrustedDevices(userId: String): List<DeviceInfo> {
        return try {
            firestore.collection("users").document(userId)
                .collection("devices")
                .get()
                .await()
                .map { doc ->
                    DeviceInfo(
                        deviceId = doc.id,
                        deviceName = doc.getString("deviceName") ?: "Unknown Device",
                        isTrusted = doc.getBoolean("trusted") ?: false,
                        lastSeen = doc.getLong("lastSeen") ?: 0L
                    )
                }
        } catch (e: Exception) {
            PrivacyLogger.e("DeviceTrustManager", "Failed to list devices: ${e.message}")
            emptyList()
        }
    }

    suspend fun registerCurrentDevice(userId: String) {
        try {
            val doc = mapOf(
                "deviceId" to deviceId,
                "deviceName" to deviceName,
                "trusted" to true,
                "revoked" to false,
                "lastSeen" to System.currentTimeMillis()
            )
            firestore.collection("users").document(userId)
                .collection("devices").document(deviceId)
                .set(doc)
                .await()
        } catch (e: Exception) {
            PrivacyLogger.e("DeviceTrustManager", "Device registration failed: ${e.message}")
        }
    }

    /**
     * Returns true if this device should be considered untrusted right now.
     *
     *  - Firestore says trusted=false  → revoked.
     *  - Firestore says trusted=true   → trusted; update last-success timestamp.
     *  - Network error: if we have a recent successful check (within TTL), keep
     *    trust; otherwise lock the vault so an attacker who throttles the network
     *    can't keep a revoked device alive forever.
     */
    suspend fun isCurrentDeviceRevoked(userId: String): Boolean {
        return try {
            val doc = firestore.collection("users").document(userId)
                .collection("devices").document(deviceId)
                .get()
                .await()
            val revoked = doc.exists() && (doc.getBoolean("trusted") == false)
            if (!revoked) {
                prefs.edit()
                    .putLong(lastSuccessfulCheckKey(userId), System.currentTimeMillis())
                    .apply()
            }
            revoked
        } catch (e: Exception) {
            val last = prefs.getLong(lastSuccessfulCheckKey(userId), 0L)
            val stale = (last == 0L) || (System.currentTimeMillis() - last > TRUST_FRESHNESS_TTL_MS)
            if (stale) {
                PrivacyLogger.w(
                    "DeviceTrustManager",
                    "Trust check failed and freshness window expired; locking."
                )
                true
            } else {
                PrivacyLogger.i("DeviceTrustManager", "Trust check failed but recent success exists; allowing.")
                false
            }
        }
    }

    suspend fun revokeDevice(userId: String, deviceId: String) {
        try {
            firestore.collection("users").document(userId)
                .collection("devices").document(deviceId)
                .update(mapOf("trusted" to false, "revoked" to true))
                .await()
        } catch (e: Exception) {
            PrivacyLogger.e("DeviceTrustManager", "Revoke failed: ${e.message}")
        }
    }
}
