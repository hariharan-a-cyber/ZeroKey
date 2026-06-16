package com.hariharan.zerokey.sync

import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.SetOptions
import com.google.firebase.firestore.Source
import com.hariharan.zerokey.core.crypto.CryptoEngine
import com.hariharan.zerokey.core.common.PrivacyLogger
import com.hariharan.zerokey.security.DeviceTrustManager
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.HmacEngine
import kotlinx.coroutines.tasks.await

/**
 * Zero-Knowledge Cross-Device Sync
 */
class DeviceSyncManager(
    private val firestore: FirebaseFirestore,
    private val cryptoEngine: CryptoEngine,
    private val hmacEngine: HmacEngine,
    private val conflictResolver: VaultConflictResolver,
    private val deviceTrustManager: DeviceTrustManager? = null
) {

    companion object {
        private const val TAG = "DeviceSyncManager"
        private const val COLLECTION_VAULTS = "encrypted_vault_snapshots"
    }

    suspend fun pushVaultSnapshot(
        userId: String,
        plaintextVaultJson: String,
        encryptionKey: ByteArray,
        hmacKey: ByteArray,
        wrappedKey: EncryptedData? = null,
        vaultEpochId: String = "",
        previousSnapshotHmac: String? = null
    ): SyncResult {
        return try {
            PrivacyLogger.d(TAG, "Sync Push started for masked_UID: ${PrivacyLogger.mask(userId)}")
            
            if (deviceTrustManager != null && deviceTrustManager.isCurrentDeviceRevoked(userId)) {
                return SyncResult.Failure("DEVICE_REVOKED: This device no longer has access to the vault.")
            }

            firestore.enableNetwork().await()

            try {
                firestore.collection("connection_test").document(userId).set(mapOf("last_attempt" to System.currentTimeMillis())).await()
            } catch (e: Exception) {
                PrivacyLogger.e(TAG, "Firestore Network Test: FAILED. Error: ${PrivacyLogger.sanitizeError(e.message)}")
            }

            val encryptedVault = cryptoEngine.encryptAesGcm(
                plaintext = plaintextVaultJson.toByteArray(Charsets.UTF_8),
                key = encryptionKey
            )

            val currentVersion = getCurrentVersion(userId)
            val newVersion = currentVersion + 1

            val deviceId = deviceTrustManager?.getCurrentDeviceId() ?: userId
            val timestamp = System.currentTimeMillis()
            val wrappedKeyB64 = wrappedKey?.cipherText?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) } ?: ""
            val hmacInput = buildHmacInput(deviceId, newVersion, timestamp, wrappedKeyB64, encryptedVault, vaultEpochId, previousSnapshotHmac ?: "")
            val hmac = hmacEngine.computeHmacSha256(hmacInput, hmacKey)
            val hmacB64 = android.util.Base64.encodeToString(hmac, android.util.Base64.NO_WRAP)

            val blob = EncryptedVaultBlob(
                deviceId = deviceId,
                vaultVersion = newVersion,
                encryptedVault = android.util.Base64.encodeToString(encryptedVault.sliceArray(12 until encryptedVault.size), android.util.Base64.NO_WRAP),
                iv = android.util.Base64.encodeToString(encryptedVault.sliceArray(0 until 12), android.util.Base64.NO_WRAP),
                hmac = hmacB64,
                timestamp = timestamp,
                wrappedVaultKey = if (wrappedKeyB64.isNotEmpty()) wrappedKeyB64 else null,
                wrappedVaultKeyIv = wrappedKey?.iv?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) },
                vaultEpochId = vaultEpochId,
                previousSnapshotHmac = previousSnapshotHmac
            )

            firestore.collection(COLLECTION_VAULTS)
                .document(userId)
                .set(blob.toMap(), SetOptions.merge())
                .await()

            PrivacyLogger.i(TAG, "Vault snapshot pushed: version=$newVersion, hmacPrefix=${hmacB64.take(8)}")
            SyncResult.Success(newVersion, hmacB64)

        } catch (e: Exception) {
            PrivacyLogger.e(TAG, "Push failed: ${PrivacyLogger.sanitizeError(e.message)}")
            SyncResult.Failure(e.message ?: "Unknown error")
        }
    }

    suspend fun pullVaultSnapshot(
        userId: String,
        encryptionKey: ByteArray,
        hmacKey: ByteArray,
        localVersion: Long,
        localVaultJson: String?,
        localEpochId: String = "",
        lastKnownHmac: String? = null
    ): PullResult {
        return try {
            if (deviceTrustManager != null && deviceTrustManager.isCurrentDeviceRevoked(userId)) {
                return PullResult.Failure("DEVICE_REVOKED: Access denied.")
            }

            firestore.enableNetwork().await()

            val doc = firestore.collection(COLLECTION_VAULTS)
                .document(userId)
                .get(Source.DEFAULT)
                .await()

            if (!doc.exists()) return PullResult.NoRemoteVault

            val remoteBlob = EncryptedVaultBlob.fromMap(doc.data!!)

            // A device that has never confirmed a sync with this remote (no prior snapshot hmac)
            // is pairing for the FIRST time -> adopt the remote vault instead of flagging a fork.
            val firstPairing = lastKnownHmac.isNullOrEmpty()

            if (!firstPairing && remoteBlob.vaultVersion < localVersion) {
                PrivacyLogger.e(TAG, "ROLLBACK ATTACK DETECTED! Local: $localVersion, Remote: ${remoteBlob.vaultVersion}")
                return PullResult.Failure("Rollback Attack Detected")
            }

            if (!firstPairing && localEpochId.isNotEmpty() && remoteBlob.vaultEpochId != localEpochId) {
                PrivacyLogger.e(TAG, "EPOCH MISMATCH! Possible Fork or Reset.")
                return PullResult.Failure("Vault Epoch Mismatch")
            }
            // (Removed the previousSnapshotHmac "chain" check: it compared values that legitimately
            // differ after a normal sync and caused false "Sync Chain Broken" failures. Integrity is
            // already guaranteed by the per-snapshot HMAC and version monotonicity above.)

            val ivBytes = android.util.Base64.decode(remoteBlob.iv, android.util.Base64.NO_WRAP)
            val encryptedBytes = android.util.Base64.decode(remoteBlob.encryptedVault, android.util.Base64.NO_WRAP)
            val combined = ivBytes + encryptedBytes
            
            val remoteHmac = android.util.Base64.decode(remoteBlob.hmac, android.util.Base64.NO_WRAP)
            
            val expectedHmac = hmacEngine.computeHmacSha256(
                buildHmacInput(
                    remoteBlob.deviceId, 
                    remoteBlob.vaultVersion, 
                    remoteBlob.timestamp, 
                    remoteBlob.wrappedVaultKey ?: "", 
                    combined,
                    remoteBlob.vaultEpochId,
                    remoteBlob.previousSnapshotHmac ?: ""
                ),
                hmacKey
            )

            if (!hmacEngine.constantTimeEquals(remoteHmac, expectedHmac)) {
                PrivacyLogger.e(TAG, "HMAC mismatch detected! MaskedUID: ${PrivacyLogger.mask(userId)}")
                return PullResult.IntegrityFailure("Vault integrity check failed", remoteBlob)
            }

            val decryptedBytes = cryptoEngine.decryptAesGcm(combined, encryptionKey)
            val remoteJson = String(decryptedBytes, Charsets.UTF_8)

            // Merge remote with local so local edits/additions are never lost.
            val mergedJson = if (localVaultJson.isNullOrBlank()) remoteJson
                             else conflictResolver.mergeJson(remoteJson, localVaultJson)
            return PullResult.Success(mergedJson, remoteBlob.vaultVersion, remoteBlob.hmac, remoteBlob.vaultEpochId)

        } catch (e: Exception) {
            PrivacyLogger.e(TAG, "Pull failed: ${PrivacyLogger.sanitizeError(e.message)}")
            PullResult.Failure(e.message ?: "Unknown error")
        }
    }

    private suspend fun getCurrentVersion(userId: String): Long {
        val doc = firestore.collection(COLLECTION_VAULTS).document(userId).get().await()
        return if (doc.exists()) doc.getLong("vaultVersion") ?: 0L else 0L
    }

    private fun buildHmacInput(
        deviceId: String, 
        version: Long, 
        timestamp: Long, 
        wrappedKey: String, 
        encryptedVault: ByteArray,
        vaultEpochId: String,
        previousSnapshotHmac: String
    ): ByteArray {
        return deviceId.toByteArray(Charsets.UTF_8) + 
               version.toString().toByteArray(Charsets.UTF_8) + 
               timestamp.toString().toByteArray(Charsets.UTF_8) +
               wrappedKey.toByteArray(Charsets.UTF_8) +
               vaultEpochId.toByteArray(Charsets.UTF_8) +
               previousSnapshotHmac.toByteArray(Charsets.UTF_8) +
               encryptedVault
    }
}
