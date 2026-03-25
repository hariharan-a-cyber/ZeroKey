package com.hariharan.zerokey.emergency

import android.util.Base64
import android.util.Log
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.security.CryptoEngine
import kotlinx.coroutines.tasks.await
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.concurrent.TimeUnit

/**
 * Hardened Emergency Access Manager.
 * Implements a signed cryptographic time-lock for vault recovery.
 *
 * Verification Layers:
 * 1. Setup signature: Owner signs (ownerUid + trustedContactUid + encryptedVaultKey).
 * 2. Request signature: Contact signs (requestId + ownerUid + requesterUid).
 * 3. 48-hour delay window.
 * 4. Owner override/cancellation (Signed).
 * 5. Manual early approval (Signed).
 */
class EmergencyAccessManager(
    private val firestore: FirebaseFirestore,
    private val cryptoEngine: CryptoEngine,
    private val notificationService: EmergencyNotificationService
) {
    companion object {
        private const val TAG = "EmergencyAccessManager"
        private const val COLLECTION_CONFIG = "emergency_access_config"
        private const val COLLECTION_REQUESTS = "emergency_access_requests"
        private val DELAY_WINDOW_MS = TimeUnit.HOURS.toMillis(48)
    }

    // ── Owner: Secure Configuration ──────────────────────────────────────────

    /**
     * Owner configures a trusted contact.
     * Verified by owner's signature to prevent server-side tampering.
     */
    suspend fun setupEmergencyAccess(
        config: EmergencyAccessConfig
    ): EmergencySetupResult {
        return try {
            val dataToVerify = config.ownerUid + config.trustedContactUid + config.encryptedVaultKey
            if (!verifySignature(dataToVerify, config.setupSignature, config.ownerPublicKey)) {
                return EmergencySetupResult.Failure("Invalid setup signature")
            }

            firestore.collection(COLLECTION_CONFIG)
                .document(config.ownerUid)
                .set(config)
                .await()

            Log.i(TAG, "Emergency Access configured for owner: ${config.ownerUid}")
            EmergencySetupResult.Success
        } catch (e: Exception) {
            Log.e(TAG, "Setup failed", e)
            EmergencySetupResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Contact: Signed Access Request ───────────────────────────────────────

    /**
     * Trusted contact requests access. 
     * Verified by contact's signature on the specific request payload.
     */
    suspend fun requestAccess(
        request: EmergencyAccessRequest
    ): AccessRequestResult {
        return try {
            val configDoc = firestore.collection(COLLECTION_CONFIG).document(request.ownerUid).get().await()
            if (!configDoc.exists()) return AccessRequestResult.NotConfigured
            
            val config = configDoc.toObject(EmergencyAccessConfig::class.java)!!

            if (config.trustedContactUid != request.requesterUid) return AccessRequestResult.Unauthorized

            // Verify contact's signature: SHA256(requestId + ownerUid + requesterUid)
            val dataToVerify = request.requestId + request.ownerUid + request.requesterUid
            if (!verifySignature(dataToVerify, request.requesterSignature, config.contactPublicKey)) {
                return AccessRequestResult.Failure("Invalid requester signature")
            }

            val idleTime = System.currentTimeMillis() - config.lastOwnerActivity
            if (idleTime < TimeUnit.DAYS.toMillis(config.inactivityDays.toLong())) {
                val remainingDays = TimeUnit.MILLISECONDS.toDays(TimeUnit.DAYS.toMillis(config.inactivityDays.toLong()) - idleTime)
                return AccessRequestResult.OwnerStillActive(remainingDays)
            }

            val approveAt = System.currentTimeMillis() + DELAY_WINDOW_MS
            val updatedRequest = request.copy(
                status = EmergencyStatus.PENDING,
                approveAt = approveAt
            )

            firestore.collection(COLLECTION_REQUESTS).document(request.requestId).set(updatedRequest).await()
            
            notificationService.notifyOwnerOfRequest(request.ownerUid, config.contactEmail, approveAt)

            AccessRequestResult.RequestAccepted(approveAt)
        } catch (e: Exception) {
            Log.e(TAG, "Access request failed", e)
            AccessRequestResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Owner: Signed Cancellation (Override) ────────────────────────────────

    /**
     * Owner can cancel any request with a signature.
     */
    suspend fun cancelRequest(ownerUid: String, requestId: String, ownerSignature: String): CancelResult {
        return try {
            val config = fetchConfig(ownerUid) ?: return CancelResult.Failure("Config not found")
            
            // Verify owner signature on cancellation: requestId + "CANCEL"
            if (!verifySignature(requestId + "CANCEL", ownerSignature, config.ownerPublicKey)) {
                return CancelResult.Failure("Invalid cancellation signature")
            }

            firestore.collection(COLLECTION_REQUESTS)
                .document(requestId)
                .update("status", EmergencyStatus.CANCELLED.name)
                .await()
            
            Log.i(TAG, "Emergency request overridden by owner.")
            CancelResult.Cancelled
        } catch (e: Exception) {
            CancelResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Owner: Signed Manual Approval ────────────────────────────────────────

    /**
     * Owner can manually approve a request before the window expires.
     */
    suspend fun manualApprove(ownerUid: String, requestId: String, ownerSignature: String): EmergencySetupResult {
        return try {
            val config = fetchConfig(ownerUid) ?: return EmergencySetupResult.Failure("Config not found")
            
            // Verify owner signature on approval: requestId + "APPROVE"
            if (!verifySignature(requestId + "APPROVE", ownerSignature, config.ownerPublicKey)) {
                return EmergencySetupResult.Failure("Invalid approval signature")
            }

            firestore.collection(COLLECTION_REQUESTS)
                .document(requestId)
                .update(mapOf(
                    "status" to EmergencyStatus.GRANTED.name,
                    "approveAt" to System.currentTimeMillis()
                ))
                .await()
            
            Log.i(TAG, "Emergency request manually approved by owner.")
            EmergencySetupResult.Success
        } catch (e: Exception) {
            EmergencySetupResult.Failure(e.message ?: "Unknown error")
        }
    }

    // ── Contact: Secure Claim ────────────────────────────────────────────────

    /**
     * Final step: Retrieve the vault key after the safety window expires.
     */
    suspend fun claimVaultKey(requestId: String): ClaimResult {
        return try {
            val requestDoc = firestore.collection(COLLECTION_REQUESTS).document(requestId).get().await()
            val request = requestDoc.toObject(EmergencyAccessRequest::class.java) ?: return ClaimResult.Failure("Request not found")

            if (request.status != EmergencyStatus.PENDING && request.status != EmergencyStatus.GRANTED) {
                return ClaimResult.NotPending
            }
            
            val now = System.currentTimeMillis()
            val approveAt = request.approveAt ?: 0L
            if (request.status == EmergencyStatus.PENDING && now < approveAt) {
                return ClaimResult.DelayNotElapsed(TimeUnit.MILLISECONDS.toHours(approveAt - now))
            }

            val configDoc = firestore.collection(COLLECTION_CONFIG).document(request.ownerUid).get().await()
            val config = configDoc.toObject(EmergencyAccessConfig::class.java)!!

            firestore.collection(COLLECTION_REQUESTS).document(requestId).update("status", EmergencyStatus.GRANTED.name).await()

            ClaimResult.Success(config.encryptedVaultKey)
        } catch (e: Exception) {
            ClaimResult.Failure(e.message ?: "Unknown error")
        }
    }

    private suspend fun fetchConfig(ownerUid: String): EmergencyAccessConfig? {
        return firestore.collection(COLLECTION_CONFIG).document(ownerUid).get().await()
            .toObject(EmergencyAccessConfig::class.java)
    }

    private fun verifySignature(data: String, signatureBase64: String, publicKeyBase64: String): Boolean {
        return try {
            val publicBytes = Base64.decode(publicKeyBase64, Base64.NO_WRAP)
            val keySpec = X509EncodedKeySpec(publicBytes)
            val keyFactory = KeyFactory.getInstance("RSA")
            val pubKey: PublicKey = keyFactory.generatePublic(keySpec)

            val sig = Signature.getInstance("SHA256withRSA")
            sig.initVerify(pubKey)
            sig.update(data.toByteArray())
            sig.verify(Base64.decode(signatureBase64, Base64.NO_WRAP))
        } catch (e: Exception) {
            Log.e(TAG, "Signature verification error", e)
            false
        }
    }
}

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
    object NotPending : ClaimResult()
    data class DelayNotElapsed(val hoursRemaining: Long) : ClaimResult()
    data class Success(val encryptedVaultKey: String) : ClaimResult()
    data class Failure(val reason: String) : ClaimResult()
}

sealed class CancelResult {
    object Cancelled : CancelResult()
    data class Failure(val reason: String) : CancelResult()
}

// ─── Notification Service ─────────────────────────────────────────────────────

interface EmergencyNotificationService {
    suspend fun notifyOwnerOfRequest(ownerId: String, contactEmail: String, cancelDeadline: Long)
    suspend fun notifyRequestCancelled(contactEmail: String)
    suspend fun notifyAccessGranted(ownerId: String, contactEmail: String)
}
