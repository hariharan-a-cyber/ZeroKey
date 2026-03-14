package com.hariharan.zerokey.sync

import android.util.Log
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.SetOptions
import com.hariharan.zerokey.security.CryptoEngine
import com.hariharan.zerokey.security.HmacEngine
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import java.util.UUID

/**
 * Zero-Knowledge Cross-Device Sync
 *
 * Security model:
 * - Vault is encrypted locally with AES-256-GCM BEFORE leaving the device
 * - Firestore only ever receives opaque ciphertext + HMAC
 * - Server-side compromise exposes zero plaintext credentials
 * - HMAC-SHA256 over (deviceId + vaultVersion + encryptedVault) prevents tampering
 */
class DeviceSyncManager(
    private val firestore: FirebaseFirestore,
    private val cryptoEngine: CryptoEngine,
    private val hmacEngine: HmacEngine,
    private val conflictResolver: VaultConflictResolver,
    private val deviceId: String = UUID.randomUUID().toString()
) {

    companion object {
        private const val TAG = "DeviceSyncManager"
        private const val COLLECTION_VAULTS = "encrypted_vaults"
    }

    /**
     * Encrypts vault locally, then uploads encrypted blob.
     * Never uploads plaintext.
     */
    suspend fun pushVault(
        userId: String,
        plaintextVaultJson: String,
        encryptionKey: ByteArray,
        hmacKey: ByteArray
    ): SyncResult {
        return try {
            // 1. Encrypt vault locally with AES-256-GCM
            val encryptedVault = cryptoEngine.encryptAesGcm(
                plaintext = plaintextVaultJson.toByteArray(Charsets.UTF_8),
                key = encryptionKey
            )

            // 2. Fetch current version to increment
            val currentVersion = getCurrentVersion(userId)
            val newVersion = currentVersion + 1

            // 3. Compute HMAC over (deviceId || vaultVersion || encryptedVault)
            val hmacInput = buildHmacInput(deviceId, newVersion, encryptedVault)
            val hmac = hmacEngine.computeHmacSha256(hmacInput, hmacKey)

            // 4. Construct blob — zero plaintext fields
            val blob = EncryptedVaultBlob(
                deviceId = deviceId,
                vaultVersion = newVersion,
                encryptedVault = android.util.Base64.encodeToString(encryptedVault.sliceArray(12 until encryptedVault.size), android.util.Base64.NO_WRAP),
                iv = android.util.Base64.encodeToString(encryptedVault.sliceArray(0 until 12), android.util.Base64.NO_WRAP),
                hmac = android.util.Base64.encodeToString(hmac, android.util.Base64.NO_WRAP),
                timestamp = System.currentTimeMillis()
            )

            // 5. Upload to Firestore
            firestore.collection(COLLECTION_VAULTS)
                .document(userId)
                .set(blob.toMap(), SetOptions.merge())
                .await()

            Log.i(TAG, "Vault pushed: version=$newVersion device=$deviceId")
            SyncResult.Success(newVersion)

        } catch (e: Exception) {
            Log.e(TAG, "Push failed", e)
            SyncResult.Failure(e.message ?: "Unknown error")
        }
    }

    /**
     * Downloads latest blob, verifies HMAC, decrypts locally.
     */
    suspend fun pullVault(
        userId: String,
        encryptionKey: ByteArray,
        hmacKey: ByteArray,
        localVersion: Long,
        localVaultJson: String?
    ): PullResult {
        return try {
            val doc = firestore.collection(COLLECTION_VAULTS)
                .document(userId)
                .get()
                .await()

            if (!doc.exists()) return PullResult.NoRemoteVault

            val blob = EncryptedVaultBlob.fromMap(doc.data!!)

            // 1. Detect conflict
            if (localVersion > 0 && blob.vaultVersion != localVersion + 1) {
                // In a simplified merge, we pass through the conflict resolver
                // return conflictResolver.resolve(blob, localBlob, encryptionKey, hmacKey)
            }

            // 2. Verify HMAC BEFORE decryption (encrypt-then-MAC)
            val ivBytes = android.util.Base64.decode(blob.iv, android.util.Base64.NO_WRAP)
            val encryptedVaultBytes = android.util.Base64.decode(blob.encryptedVault, android.util.Base64.NO_WRAP)
            val combined = ivBytes + encryptedVaultBytes
            
            val remoteHmac = android.util.Base64.decode(blob.hmac, android.util.Base64.NO_WRAP)
            val expectedHmac = hmacEngine.computeHmacSha256(
                buildHmacInput(blob.deviceId, blob.vaultVersion, combined),
                hmacKey
            )

            if (!hmacEngine.constantTimeEquals(remoteHmac, expectedHmac)) {
                Log.e(TAG, "HMAC verification failed — possible tampering!")
                return PullResult.IntegrityFailure("HMAC mismatch: vault may be tampered")
            }

            // 3. Decrypt locally
            val decryptedBytes = cryptoEngine.decryptAesGcm(combined, encryptionKey)
            val plaintextVault = String(decryptedBytes, Charsets.UTF_8)

            Log.i(TAG, "Vault pulled and verified: version=${blob.vaultVersion}")
            PullResult.Success(plaintextVault, blob.vaultVersion)

        } catch (e: Exception) {
            Log.e(TAG, "Pull failed", e)
            PullResult.Failure(e.message ?: "Unknown error")
        }
    }

    private suspend fun getCurrentVersion(userId: String): Long {
        val doc = firestore.collection(COLLECTION_VAULTS).document(userId).get().await()
        return if (doc.exists()) doc.getLong("vaultVersion") ?: 0L else 0L
    }

    private fun buildHmacInput(deviceId: String, version: Long, encryptedVaultWithIv: ByteArray): ByteArray {
        return deviceId.toByteArray(Charsets.UTF_8) + 
               version.toString().toByteArray(Charsets.UTF_8) + 
               encryptedVaultWithIv
    }
}
