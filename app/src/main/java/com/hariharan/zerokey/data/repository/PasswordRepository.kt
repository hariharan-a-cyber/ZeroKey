package com.hariharan.zerokey.data.repository

import android.content.Context
import android.util.Base64
import com.hariharan.zerokey.core.database.PasswordDao
import com.hariharan.zerokey.core.database.PasswordEntity
import com.hariharan.zerokey.core.database.VaultMetadata
import com.hariharan.zerokey.core.database.VaultMetadataDao
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.security.MasterPasswordManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.spec.SecretKeySpec
import java.security.SecureRandom
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Phase 2: Vault Storage System.
 * Sole cleartext gateway. Handles all encryption/decryption before DB access.
 * Refactored to use Envelope Encryption and Associated Authenticated Data (AAD).
 * Performance: Uses Lazy Decryption via PasswordItem.
 */
@Singleton
class PasswordRepository @Inject constructor(
    private val passwordDao: PasswordDao,
    private val vaultMetadataDao: VaultMetadataDao? = null,
    private val masterPasswordManager: MasterPasswordManager,
    private val encryptionManager: EncryptionManager
) {

    suspend fun getPasswords(): List<PasswordItem> = withContext(Dispatchers.IO) {
        passwordDao.getAllPasswords().map { 
            PasswordItem(
                id = it.id, 
                encryptedEntity = it, 
                isFavorite = it.isFavorite, 
                masterPasswordManager = masterPasswordManager, 
                encryptionManager = encryptionManager
            ) 
        }
    }

    suspend fun getAllEntities(): List<PasswordEntity> = withContext(Dispatchers.IO) {
        passwordDao.getAllPasswords()
    }

    suspend fun syncEntity(entity: PasswordEntity) = withContext(Dispatchers.IO) {
        passwordDao.insertPassword(entity)
    }

    suspend fun deletePassword(id: Int) = withContext(Dispatchers.IO) {
        passwordDao.deletePasswordById(id)
    }

    suspend fun getPasswordById(id: Int): PasswordItem? = withContext(Dispatchers.IO) {
        passwordDao.getPasswordById(id)?.let { 
            PasswordItem(
                id = it.id, 
                encryptedEntity = it, 
                isFavorite = it.isFavorite, 
                masterPasswordManager = masterPasswordManager, 
                encryptionManager = encryptionManager
            ) 
        }
    }

    suspend fun updateFavorite(id: Int, isFavorite: Boolean) = withContext(Dispatchers.IO) {
        passwordDao.updateFavorite(id, isFavorite)
    }

    suspend fun getVaultVersion(): Long = withContext(Dispatchers.IO) {
        vaultMetadataDao?.getMetadata()?.vaultVersion ?: 0L
    }

    suspend fun getVaultEpochId(): String = withContext(Dispatchers.IO) {
        val current = vaultMetadataDao?.getMetadata()
        if (current != null && current.vaultEpochId.isNotEmpty()) {
            current.vaultEpochId
        } else {
            val newEpoch = java.util.UUID.randomUUID().toString()
            if (current != null) {
                vaultMetadataDao?.updateMetadata(current.copy(vaultEpochId = newEpoch))
            } else {
                vaultMetadataDao?.updateMetadata(VaultMetadata(vaultVersion = 0, lastSyncTimestamp = 0, deviceId = "local", vaultEpochId = newEpoch))
            }
            newEpoch
        }
    }

    suspend fun getLastKnownHmac(): String? = withContext(Dispatchers.IO) {
        vaultMetadataDao?.getMetadata()?.lastKnownHmac
    }

    suspend fun updateVaultVersion(newVersion: Long, hmac: String? = null) = withContext(Dispatchers.IO) {
        val current = vaultMetadataDao?.getMetadata()
        if (current != null) {
            vaultMetadataDao.updateMetadata(current.copy(
                vaultVersion = newVersion, 
                lastSyncTimestamp = System.currentTimeMillis(),
                lastKnownHmac = hmac ?: current.lastKnownHmac
            ))
        } else {
            vaultMetadataDao?.updateMetadata(VaultMetadata(
                vaultVersion = newVersion, 
                lastSyncTimestamp = System.currentTimeMillis(), 
                deviceId = "local",
                lastKnownHmac = hmac
            ))
        }
    }

    suspend fun syncWithRemote(remoteEntities: List<PasswordEntity>) = withContext(Dispatchers.IO) {
        // Implement record-level synchronization
        val localEntities = passwordDao.getAllPasswords().associateBy { it.id }
        
        remoteEntities.forEach { remote ->
            val local = localEntities[remote.id]
            if (local == null || remote.lastModified > local.lastModified) {
                passwordDao.insertPassword(remote)
            }
        }
    }

    suspend fun savePassword(service: String, username: String, password: String, notes: String? = null, id: Int = 0) = withContext(Dispatchers.IO) {
        val vaultKey = masterPasswordManager.getVaultKey() 
            ?: throw IllegalStateException("Vault must be unlocked before saving passwords")

        // If updating, preserve original creation time and favorite status
        var existingEntity: PasswordEntity? = null
        if (id != 0) {
            existingEntity = passwordDao.getPasswordById(id)
        }

        val createdAt = existingEntity?.createdAt ?: System.currentTimeMillis()
        val isFavorite = existingEntity?.isFavorite ?: false
        val recordUid = existingEntity?.recordUid ?: java.util.UUID.randomUUID().toString()
        val version = 1
        val schemaVersion = 6
        
        // CRITICAL: We bind the ciphertext to the record's unique ID, creation time, and SCHEMA version.
        // This prevents "Cut-and-Paste" attacks and future migration ambiguity.
        val aad = "v$version|s$schemaVersion|$recordUid|$createdAt".toByteArray(Charsets.UTF_8)

        val serviceNameEnc = encryptionManager.encryptWithKey(service.toByteArray(), vaultKey, aad)
        val usernameEnc = encryptionManager.encryptWithKey(username.toByteArray(), vaultKey, aad)
        val passwordEnc = encryptionManager.encryptWithKey(password.toByteArray(), vaultKey, aad)
        val notesEnc = notes?.let { encryptionManager.encryptWithKey(it.toByteArray(), vaultKey, aad) }

        val entity = PasswordEntity(
            id = id,
            encryptedServiceName = Base64.encodeToString(serviceNameEnc.cipherText, Base64.NO_WRAP),
            serviceNameIv = Base64.encodeToString(serviceNameEnc.iv, Base64.NO_WRAP),
            encryptedUsername = Base64.encodeToString(usernameEnc.cipherText, Base64.NO_WRAP),
            usernameIv = Base64.encodeToString(usernameEnc.iv, Base64.NO_WRAP),
            encryptedPassword = Base64.encodeToString(passwordEnc.cipherText, Base64.NO_WRAP),
            passwordIv = Base64.encodeToString(passwordEnc.iv, Base64.NO_WRAP),
            encryptedNotes = notesEnc?.let { Base64.encodeToString(it.cipherText, Base64.NO_WRAP) },
            notesIv = notesEnc?.let { Base64.encodeToString(it.iv, Base64.NO_WRAP) },
            isFavorite = isFavorite,
            createdAt = createdAt,
            lastModified = System.currentTimeMillis(),
            recordUid = recordUid,
            encryptionVersion = version,
            schemaVersion = schemaVersion
        )
        passwordDao.insertPassword(entity)
    }

    /**
     * Generates a new random Vault Key and re-encrypts all entries.
     * Use for emergency recovery or compromised device scenarios.
     */
    suspend fun rotateVaultKey(context: Context) = withContext(Dispatchers.IO) {
        val oldVaultKey = masterPasswordManager.getVaultKey()
            ?: throw IllegalStateException("Vault must be unlocked")
        
        // 1. Generate NEW random 256-bit Vault Key
        val rawNewKey = ByteArray(32)
        SecureRandom().nextBytes(rawNewKey)
        val newVaultKey = SecretKeySpec(rawNewKey, "AES")

        // 2. Load and Re-encrypt every item
        val items = getPasswords()
        items.forEach { item ->
            val service = item.serviceName
            val username = item.username
            val password = item.password
            val notes = item.notes
            
            // Re-save using the new in-memory temporary key
            // (We'll update MasterPasswordManager at the end)
            saveWithSpecificKey(service, username, password, notes, item.id, newVaultKey, item.toEntity())
        }

        // 3. Update masterPasswordManager to use and persist the new key
        val wrappedNewKey = encryptionManager.encryptWithKey(rawNewKey, masterPasswordManager.getSessionKey()!!)
        masterPasswordManager.importVaultKey(context, wrappedNewKey)
        
        // 4. Reset Epoch for a clean cryptographic break
        val newEpoch = java.util.UUID.randomUUID().toString()
        val current = vaultMetadataDao?.getMetadata()
        if (current != null) {
            vaultMetadataDao.updateMetadata(current.copy(
                vaultEpochId = newEpoch,
                vaultVersion = 0, // Reset version for new epoch
                lastKnownHmac = null // Reset chain
            ))
        } else {
            vaultMetadataDao?.updateMetadata(VaultMetadata(vaultVersion = 0, lastSyncTimestamp = 0, deviceId = "local", vaultEpochId = newEpoch))
        }
        
        rawNewKey.fill(0)
    }

    private suspend fun saveWithSpecificKey(
        service: String, 
        username: String, 
        password: String, 
        notes: String?, 
        id: Int, 
        key: SecretKeySpec,
        existing: PasswordEntity
    ) {
        val aad = "v${existing.encryptionVersion}|s${existing.schemaVersion}|${existing.recordUid}|${existing.createdAt}".toByteArray(Charsets.UTF_8)
        
        val serviceNameEnc = encryptionManager.encryptWithKey(service.toByteArray(), key, aad)
        val usernameEnc = encryptionManager.encryptWithKey(username.toByteArray(), key, aad)
        val passwordEnc = encryptionManager.encryptWithKey(password.toByteArray(), key, aad)
        val notesEnc = notes?.let { encryptionManager.encryptWithKey(it.toByteArray(), key, aad) }

        val entity = existing.copy(
            encryptedServiceName = Base64.encodeToString(serviceNameEnc.cipherText, Base64.NO_WRAP),
            serviceNameIv = Base64.encodeToString(serviceNameEnc.iv, Base64.NO_WRAP),
            encryptedUsername = Base64.encodeToString(usernameEnc.cipherText, Base64.NO_WRAP),
            usernameIv = Base64.encodeToString(usernameEnc.iv, Base64.NO_WRAP),
            encryptedPassword = Base64.encodeToString(passwordEnc.cipherText, Base64.NO_WRAP),
            passwordIv = Base64.encodeToString(passwordEnc.iv, Base64.NO_WRAP),
            encryptedNotes = notesEnc?.let { Base64.encodeToString(it.cipherText, Base64.NO_WRAP) },
            notesIv = notesEnc?.let { Base64.encodeToString(it.iv, Base64.NO_WRAP) },
            lastModified = System.currentTimeMillis()
        )
        passwordDao.insertPassword(entity)
    }
}
