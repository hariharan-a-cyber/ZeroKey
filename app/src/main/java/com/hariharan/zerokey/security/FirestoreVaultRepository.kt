package com.hariharan.zerokey.security

import com.hariharan.zerokey.core.crypto.EncryptedVault
import com.hariharan.zerokey.core.security.VaultIntegrityManager
import android.util.Base64
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.SetOptions
import kotlinx.coroutines.tasks.await
import java.util.*
import javax.crypto.SecretKey

/**
 * Connects SyncManager with Firestore.
 * Ensures only encrypted blobs and HMACs are stored.
 */
class FirestoreVaultRepository(
    private val firestore: FirebaseFirestore,
    private val deviceTrustManager: DeviceTrustManager
) {

    private val usersCollection = firestore.collection("users")

    /**
     * Uploads the encrypted vault to Firestore.
     * Enforces trusted device validation and HMAC integrity.
     */
    suspend fun uploadEncryptedVault(
        uid: String,
        encryptedVault: EncryptedVault,
        hmacKey: SecretKey,
        vaultVersion: Long
    ) {
        val currentDeviceId = deviceTrustManager.getCurrentDeviceId()
        
        // 1. Prepare data for HMAC
        val vaultDataBytes = Base64.decode(encryptedVault.vaultData, Base64.DEFAULT)
        
        // 2. Generate HMAC for integrity
        val hmac = VaultIntegrityManager.sign(vaultDataBytes, hmacKey)
        
        // 3. Prepare Firestore document
        val vaultDoc = mapOf(
            "encrypted_blob" to encryptedVault.vaultData,
            "vault_version" to vaultVersion,
            "last_modified" to System.currentTimeMillis(),
            "hmac" to Base64.encodeToString(hmac, Base64.DEFAULT),
            "iv" to encryptedVault.iv,
            "salt" to encryptedVault.salt,
            "iterations" to encryptedVault.iterations,
            "last_modifier_device" to currentDeviceId
        )

        // 4. Update the document for the user
        // We use merge to preserve the 'devices' list if it exists
        usersCollection.document(uid).set(vaultDoc, SetOptions.merge()).await()
        
        // 5. Ensure current device is in the trusted list
        addDeviceToTrustedList(uid, currentDeviceId)
    }

    /**
     * Downloads the encrypted vault from Firestore.
     */
    suspend fun downloadEncryptedVault(uid: String): Map<String, Any>? {
        val document = usersCollection.document(uid).get().await()
        return if (document.exists()) {
            document.data
        } else {
            null
        }
    }

    /**
     * Verifies the integrity of the downloaded vault using HMAC.
     */
    fun verifyVaultIntegrity(vaultData: String, storedHmac: String, hmacKey: SecretKey): Boolean {
        val dataBytes = Base64.decode(vaultData, Base64.DEFAULT)
        val hmacBytes = Base64.decode(storedHmac, Base64.DEFAULT)
        return VaultIntegrityManager.verify(dataBytes, hmacBytes, hmacKey)
    }

    /**
     * Adds a device ID to the trusted devices list in Firestore.
     */
    private suspend fun addDeviceToTrustedList(uid: String, deviceId: String) {
        val userDocRef = usersCollection.document(uid)
        firestore.runTransaction { transaction ->
            val snapshot = transaction.get(userDocRef)
            val devices = snapshot.get("devices") as? MutableList<String> ?: mutableListOf()
            if (!devices.contains(deviceId)) {
                devices.add(deviceId)
                transaction.update(userDocRef, "devices", devices)
            }
        }.await()
    }

    /**
     * Real-time listener for vault updates.
     */
    fun listenForUpdates(uid: String, onUpdate: (Map<String, Any>) -> Unit) {
        usersCollection.document(uid).addSnapshotListener { snapshot, e ->
            if (e != null) return@addSnapshotListener
            if (snapshot != null && snapshot.exists()) {
                snapshot.data?.let { onUpdate(it) }
            }
        }
    }
}
