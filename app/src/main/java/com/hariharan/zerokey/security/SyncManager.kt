package com.hariharan.zerokey.security

import com.hariharan.zerokey.core.crypto.EncryptedVault
import android.util.Base64
import com.hariharan.zerokey.core.database.PasswordEntity
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.sync.VaultSerializer
import javax.crypto.SecretKey

/**
 * Handles End-to-End Encrypted Cloud Sync using Firestore.
 * Ensures Zero-Knowledge: Only ciphertext and HMACs are handled here.
 */
class SyncManager(
    private val repository: PasswordRepository,
    private val serializer: VaultSerializer,
    private val firestoreVaultRepository: FirestoreVaultRepository,
    private val authenticator: FirebaseAuthenticator,
    private val deviceTrustManager: DeviceTrustManager
) {

    /**
     * Uploads the local vault to Firestore after encryption and signing.
     */
    suspend fun uploadEncryptedVault(masterKey: SecretKey, hmacKey: SecretKey, salt: String) {
        val uid = authenticator.uid ?: throw IllegalStateException("User not authenticated")
        
        // 1. Get current entities
        val entities = repository.getAllEntities()
        
        // 2. Serialize and Encrypt (Zero-Knowledge)
        val encryptedVault = serializer.serialize(
            entities = entities,
            vaultVersion = System.currentTimeMillis(),
            masterKey = masterKey,
            hmacKey = hmacKey,
            salt = salt
        )
        
        // 3. Upload to Firestore (includes HMAC and device trust)
        firestoreVaultRepository.uploadEncryptedVault(
            uid = uid,
            encryptedVault = encryptedVault,
            hmacKey = hmacKey,
            vaultVersion = System.currentTimeMillis()
        )
    }

    /**
     * Downloads and merges the remote vault with the local database.
     */
    suspend fun downloadAndMergeVault(masterKey: SecretKey, hmacKey: SecretKey) {
        val uid = authenticator.uid ?: throw IllegalStateException("User not authenticated")
        
        // 1. Check Device Trust
        // In a real implementation, we would check if the current device is in the trusted list
        // if (!deviceTrustManager.isCurrentDeviceTrusted(uid)) { ... }

        val remoteData = firestoreVaultRepository.downloadEncryptedVault(uid) ?: return
        
        val vaultData = remoteData["encrypted_blob"] as String
        val storedHmac = remoteData["hmac"] as String
        val iv = remoteData["iv"] as String
        val salt = remoteData["salt"] as String
        
        // 2. Verify Integrity (HMAC) before decryption
        if (!firestoreVaultRepository.verifyVaultIntegrity(vaultData, storedHmac, hmacKey)) {
            throw SecurityException("Vault integrity check failed!")
        }
        
        // 3. Decrypt (Zero-Knowledge)
        val encryptedVault = EncryptedVault(
            vaultData = vaultData,
            salt = salt,
            iv = iv
        )
        
        val remoteEntities = serializer.deserialize(encryptedVault, masterKey)
        
        // 4. Apply Merge (Latest Modified Wins)
        applyVaultMerge(remoteEntities)
    }

    /**
     * Conflict resolution logic: Latest modified wins.
     */
    suspend fun applyVaultMerge(remoteEntities: List<PasswordEntity>) {
        val localEntities = repository.getAllEntities()
        
        remoteEntities.forEach { remote ->
            val local = localEntities.find { it.id == remote.id }
            if (local == null || remote.lastModified > local.lastModified) {
                // Remote is newer or doesn't exist locally
                repository.syncEntity(remote)
            }
        }
    }

    /**
     * Real-time sync setup.
     */
    fun startRealTimeSync(masterKey: SecretKey, hmacKey: SecretKey) {
        val uid = authenticator.uid ?: return
        firestoreVaultRepository.listenForUpdates(uid) { _ ->
            // Logic to trigger sync
        }
    }
}
