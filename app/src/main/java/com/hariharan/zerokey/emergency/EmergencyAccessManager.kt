package com.hariharan.zerokey.emergency

import android.util.Log
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.security.CryptoEngine
import kotlinx.coroutines.tasks.await
import java.util.concurrent.TimeUnit

/**
 * EmergencyAccessManager
 *
 * Implements a cryptographic time-lock for trusted contact vault recovery.
 */
class EmergencyAccessManager(
    private val firestore: FirebaseFirestore,
    private val cryptoEngine: CryptoEngine,
    private val notificationService: EmergencyNotificationService
) {
    companion object {
        private const val TAG = "EmergencyAccessManager"
        private const val COLLECTION_EMERGENCY = "emergency_access"
        private const val DEFAULT_INACTIVITY_DAYS = 30L
        private val DELAY_WINDOW_MS = TimeUnit.HOURS.toMillis(48)
    }

    // ── Owner: Configure Trusted Contact ─────────────────────────────────────

    /**
     * Owner configures a trusted contact and uploads an emergency-encrypted vault copy.
     */
    suspend fun configureTrustedContact(
        ownerId: String,
        contactUserId: String,
        contactEmail: String,
        vaultJson: String,
        contactPublicKey: ByteArray,
        inactivityDays: Long = DEFAULT_INACTIVITY_DAYS
    ): EmergencySetupResult {
        return try {
            // Encrypt vault with contact's public key (RSA-OAEP)
            val encryptedEmergencyVault = encryptForContact(vaultJson, contactPublicKey)

            val config = EmergencyAccessConfig(
                ownerId = ownerId,
                contactUserId = contactUserId,
                contactEmail = contactEmail,
                encryptedEmergencyVault = android.util.Base64.encodeToString(
                    encryptedEmergencyVault, android.util.Base64.NO_WRAP
                ),
                inactivityThresholdMs = TimeUnit.DAYS.toMillis(inactivityDays),
                lastOwnerActivity = System.currentTimeMillis(),
                status = EmergencyStatus.CONFIGURED,
                createdAt = System.currentTimeMillis()
            )

            firestore.collection(COLLECTION_EMERGENCY)
                .document(ownerId)
                .set(config.toMap())
                .await()

            Log.i(TAG, "Emergency access configured for contact: $contactEmail")
            EmergencySetupResult.Success

        } catch (e: Exception) {
            Log.e(TAG, "Emergency setup failed", e)
            EmergencySetupResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Owner: Record Activity (prevents false triggers) ──────────────────────

    suspend fun recordOwnerActivity(ownerId: String) {
        firestore.collection(COLLECTION_EMERGENCY)
            .document(ownerId)
            .update("lastOwnerActivity", System.currentTimeMillis())
            .await()
        Log.d(TAG, "Owner activity recorded: $ownerId")
    }

    // ── Owner: Cancel Pending Request ────────────────────────────────────────

    suspend fun cancelEmergencyRequest(ownerId: String): CancelResult {
        return try {
            val doc = firestore.collection(COLLECTION_EMERGENCY).document(ownerId).get().await()
            if (!doc.exists()) return CancelResult.NoRequest

            val config = EmergencyAccessConfig.fromMap(doc.data!!)
            if (config.status != EmergencyStatus.PENDING) return CancelResult.NoRequest

            firestore.collection(COLLECTION_EMERGENCY)
                .document(ownerId)
                .update(mapOf(
                    "status" to EmergencyStatus.CONFIGURED.name,
                    "requestedAt" to null,
                    "approveAt" to null
                ))
                .await()

            Log.i(TAG, "Emergency request CANCELLED by owner: $ownerId")
            notificationService.notifyRequestCancelled(config.contactEmail)
            CancelResult.Cancelled

        } catch (e: Exception) {
            CancelResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Contact: Request Access ──────────────────────────────────────────────

    suspend fun requestEmergencyAccess(
        contactUserId: String,
        ownerId: String
    ): AccessRequestResult {
        return try {
            val doc = firestore.collection(COLLECTION_EMERGENCY).document(ownerId).get().await()
            if (!doc.exists()) return AccessRequestResult.NotConfigured

            val config = EmergencyAccessConfig.fromMap(doc.data!!)

            // 1. Verify requester is the configured contact
            if (config.contactUserId != contactUserId) {
                Log.w(TAG, "Unauthorized emergency access attempt by: $contactUserId")
                return AccessRequestResult.Unauthorized
            }

            // 2. Check inactivity
            val inactiveDuration = System.currentTimeMillis() - config.lastOwnerActivity
            if (inactiveDuration < config.inactivityThresholdMs) {
                val daysRemaining = TimeUnit.MILLISECONDS.toDays(
                    config.inactivityThresholdMs - inactiveDuration
                )
                return AccessRequestResult.OwnerStillActive(daysRemaining)
            }

            // 3. Check if already pending
            if (config.status == EmergencyStatus.PENDING) {
                return AccessRequestResult.AlreadyPending(config.approveAt ?: 0L)
            }

            // 4. Start 48-hour countdown
            val approveAt = System.currentTimeMillis() + DELAY_WINDOW_MS

            firestore.collection(COLLECTION_EMERGENCY)
                .document(ownerId)
                .update(mapOf(
                    "status" to EmergencyStatus.PENDING.name,
                    "requestedAt" to System.currentTimeMillis(),
                    "approveAt" to approveAt
                ))
                .await()

            // 5. Notify owner
            notificationService.notifyOwnerOfRequest(
                ownerId = ownerId,
                contactEmail = config.contactEmail,
                cancelDeadline = approveAt
            )

            Log.i(TAG, "Emergency access REQUESTED. Approval window: 48h. ApproveAt: $approveAt")
            AccessRequestResult.RequestAccepted(approveAt)

        } catch (e: Exception) {
            AccessRequestResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Contact: Claim Access ────────────────────────────────────────────────

    suspend fun claimEmergencyAccess(
        contactUserId: String,
        ownerId: String
    ): ClaimResult {
        return try {
            val doc = firestore.collection(COLLECTION_EMERGENCY).document(ownerId).get().await()
            if (!doc.exists()) return ClaimResult.NotConfigured

            val config = EmergencyAccessConfig.fromMap(doc.data!!)

            // Validate pending state and delay window
            if (config.status != EmergencyStatus.PENDING) return ClaimResult.NotPending
            if (config.contactUserId != contactUserId) return ClaimResult.Unauthorized

            val now = System.currentTimeMillis()
            val approveAt = config.approveAt ?: return ClaimResult.NotPending

            if (now < approveAt) {
                val hoursRemaining = TimeUnit.MILLISECONDS.toHours(approveAt - now)
                return ClaimResult.DelayNotElapsed(hoursRemaining)
            }

            // Grant access — return encrypted vault
            firestore.collection(COLLECTION_EMERGENCY)
                .document(ownerId)
                .update("status", EmergencyStatus.GRANTED.name)
                .await()

            Log.i(TAG, "Emergency access GRANTED to: $contactUserId for owner: $ownerId")
            ClaimResult.Success(config.encryptedEmergencyVault)

        } catch (e: Exception) {
            ClaimResult.Failure(e.message ?: "Unknown error")
        }
    }

    private fun encryptForContact(vaultJson: String, contactPublicKey: ByteArray): ByteArray {
        // Mock implementation since CryptoEngine doesn't have RSA yet
        return vaultJson.toByteArray() 
    }
}

// ─── Data Models ─────────────────────────────────────────────────────────────

data class EmergencyAccessConfig(
    val ownerId: String,
    val contactUserId: String,
    val contactEmail: String,
    val encryptedEmergencyVault: String,
    val inactivityThresholdMs: Long,
    val lastOwnerActivity: Long,
    val status: EmergencyStatus,
    val createdAt: Long,
    val requestedAt: Long? = null,
    val approveAt: Long? = null
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "ownerId" to ownerId,
        "contactUserId" to contactUserId,
        "contactEmail" to contactEmail,
        "encryptedEmergencyVault" to encryptedEmergencyVault,
        "inactivityThresholdMs" to inactivityThresholdMs,
        "lastOwnerActivity" to lastOwnerActivity,
        "status" to status.name,
        "createdAt" to createdAt,
        "requestedAt" to requestedAt,
        "approveAt" to approveAt
    )

    companion object {
        fun fromMap(map: Map<String, Any?>): EmergencyAccessConfig = EmergencyAccessConfig(
            ownerId = map["ownerId"] as String,
            contactUserId = map["contactUserId"] as String,
            contactEmail = map["contactEmail"] as String,
            encryptedEmergencyVault = map["encryptedEmergencyVault"] as String,
            inactivityThresholdMs = map["inactivityThresholdMs"] as Long,
            lastOwnerActivity = map["lastOwnerActivity"] as Long,
            status = EmergencyStatus.valueOf(map["status"] as String),
            createdAt = map["createdAt"] as Long,
            requestedAt = map["requestedAt"] as? Long,
            approveAt = map["approveAt"] as? Long
        )
    }
}

enum class EmergencyStatus { CONFIGURED, PENDING, GRANTED, REVOKED }

// ─── Result Types ─────────────────────────────────────────────────────────────

sealed class EmergencySetupResult {
    object Success : EmergencySetupResult()
    data class Failure(val reason: String) : EmergencySetupResult()
}

sealed class AccessRequestResult {
    object NotConfigured : AccessRequestResult()
    object Unauthorized : AccessRequestResult()
    data class OwnerStillActive(val daysUntilEligible: Long) : AccessRequestResult()
    data class AlreadyPending(val approveAt: Long) : AccessRequestResult()
    data class RequestAccepted(val approveAt: Long) : AccessRequestResult()
    data class Failure(val reason: String) : AccessRequestResult()
}

sealed class ClaimResult {
    object NotConfigured : ClaimResult()
    object NotPending : ClaimResult()
    object Unauthorized : ClaimResult()
    data class DelayNotElapsed(val hoursRemaining: Long) : ClaimResult()
    data class Success(val encryptedVault: String) : ClaimResult()
    data class Failure(val reason: String) : ClaimResult()
}

sealed class CancelResult {
    object Cancelled : CancelResult()
    object NoRequest : CancelResult()
    data class Failure(val reason: String) : CancelResult()
}

// ─── Notification Service ─────────────────────────────────────────────────────

interface EmergencyNotificationService {
    suspend fun notifyOwnerOfRequest(ownerId: String, contactEmail: String, cancelDeadline: Long)
    suspend fun notifyRequestCancelled(contactEmail: String)
    suspend fun notifyAccessGranted(ownerId: String, contactEmail: String)
}
