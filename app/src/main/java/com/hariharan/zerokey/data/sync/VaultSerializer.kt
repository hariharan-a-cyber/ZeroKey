package com.hariharan.zerokey.data.sync

import android.util.Base64
import com.hariharan.zerokey.core.database.PasswordEntity
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.EncryptedVault
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.security.VaultIntegrityManager
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import javax.crypto.SecretKey

/**
 * Responsible for serializing the entire vault into an encrypted blob.
 * Follows zero-knowledge principles.
 */
class VaultSerializer(
    private val encryptionManager: EncryptionManager
) {

    @Serializable
    private data class VaultPayload(
        val version: Long,
        val entities: List<PasswordEntity>,
        val timestamp: Long
    )

    /**
     * Converts Room database entries into an EncryptedVault object.
     */
    fun serialize(
        entities: List<PasswordEntity>,
        vaultVersion: Long,
        masterKey: SecretKey,
        hmacKey: SecretKey,
        salt: String
    ): EncryptedVault {
        val payload = VaultPayload(
            version = vaultVersion,
            entities = entities,
            timestamp = System.currentTimeMillis()
        )
        
        val jsonPayload = Json.encodeToString(payload)
        
        // Use hardened EncryptionManager
        val encryptedData = encryptionManager.encryptWithKey(jsonPayload.toByteArray(Charsets.UTF_8), masterKey)
        
        val ciphertextBase64 = Base64.encodeToString(encryptedData.cipherText, Base64.NO_WRAP)
        
        // Generate HMAC for integrity protection
        val hmac = VaultIntegrityManager.sign(encryptedData.cipherText, hmacKey)
        val hmacBase64 = Base64.encodeToString(hmac, Base64.NO_WRAP)

        return EncryptedVault(
            vaultData = ciphertextBase64,
            salt = salt,
            iv = Base64.encodeToString(encryptedData.iv, Base64.NO_WRAP),
            iterations = 4 // Argon2id time cost (matches KeyDerivationManager LATEST_VERSION)
        )
    }

    /**
     * Decrypts an EncryptedVault blob back into Room database entries.
     */
    fun deserialize(
        encryptedVault: EncryptedVault,
        masterKey: SecretKey
    ): List<PasswordEntity> {
        val cipherText = Base64.decode(encryptedVault.vaultData, Base64.NO_WRAP)
        val iv = Base64.decode(encryptedVault.iv, Base64.NO_WRAP)
        
        val encryptedData = EncryptedData(cipherText, iv)
        
        // Use hardened EncryptionManager
        val decryptedBytes = encryptionManager.decryptWithKey(encryptedData, masterKey)
        val jsonPayload = String(decryptedBytes, Charsets.UTF_8)
        
        val payload = Json.decodeFromString<VaultPayload>(jsonPayload)
        return payload.entities
    }
}
