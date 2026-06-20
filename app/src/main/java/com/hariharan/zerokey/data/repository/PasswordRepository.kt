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
    private val masterPasswordManager: MasterPasswordManager,
    private val encryptionManager: EncryptionManager,
    private val vaultMetadataDao: VaultMetadataDao
) {

    suspend fun getPasswords(): List<PasswordItem> = withContext(Dispatchers.IO) {
        passwordDao.getAllPasswordsList().map { entity ->
            PasswordItem(
                id = entity.id, 
                encryptedEntity = entity, 
                isFavorite = entity.isFavorite, 
                masterPasswordManager = masterPasswordManager, 
                encryptionManager = encryptionManager
            ) 
        }
    }

    suspend fun getAllEntities(): List<PasswordEntity> = withContext(Dispatchers.IO) {
        passwordDao.getAllPasswordsList()
    }

    /**
     * Persist a breach-check result so we don't re-ping HIBP for the same password.
     * Used by PasswordHealthAnalyzer to cache results for ~7 days per credential.
     */
    suspend fun markBreachChecked(id: Int, breached: Boolean) {
        val entity = passwordDao.getPasswordById(id) ?: return
        passwordDao.update(entity.copy(
            lastBreachCheck = System.currentTimeMillis(),
            breachFound = breached
        ))
    }

    suspend fun syncEntity(entity: PasswordEntity) = withContext(Dispatchers.IO) {
        passwordDao.insertPassword(entity)
    }

    suspend fun deletePassword(id: Int) = withContext(Dispatchers.IO) {
        passwordDao.deletePasswordById(id)
    }

    suspend fun getPasswordById(id: Int): PasswordItem? = withContext(Dispatchers.IO) {
        passwordDao.getPasswordById(id)?.let { entity ->
            PasswordItem(
                id = entity.id, 
                encryptedEntity = entity, 
                isFavorite = entity.isFavorite,
                masterPasswordManager = masterPasswordManager, 
                encryptionManager = encryptionManager
            ) 
        }
    }

    private fun decryptField(ciphertext: String, iv: String, createdAt: Long, entity: PasswordEntity): String {
        val vaultKey = masterPasswordManager.getVaultKey() ?: return "[Vault Locked]"
        val version = entity.encryptionVersion
        val recordUid = entity.recordUid ?: ""
        val sVersion = entity.schemaVersion
        val aad = "v$version|s$sVersion|$recordUid|$createdAt".toByteArray(Charsets.UTF_8)
        val data = EncryptedData(Base64.decode(ciphertext, Base64.NO_WRAP), Base64.decode(iv, Base64.NO_WRAP))
        return try {
            encryptionManager.decryptWithKey(data, vaultKey, aad).decodeToString()
        } catch (e: Exception) {
            "[Decryption Error]"
        }
    }

    suspend fun updateFavorite(id: Int, isFavorite: Boolean) = withContext(Dispatchers.IO) {
        passwordDao.updateFavorite(id, isFavorite)
    }

    suspend fun getVaultVersion(): Long = withContext(Dispatchers.IO) {
        vaultMetadataDao.getMetadata()?.vaultVersion ?: 0L
    }

    suspend fun getVaultEpochId(): String = withContext(Dispatchers.IO) {
        val current = vaultMetadataDao.getMetadata()
        if (current != null && current.vaultEpochId.isNotEmpty()) {
            current.vaultEpochId
        } else {
            val newEpoch = java.util.UUID.randomUUID().toString()
            if (current != null) {
                vaultMetadataDao.updateMetadata(current.copy(vaultEpochId = newEpoch))
            } else {
                vaultMetadataDao.updateMetadata(VaultMetadata(vaultVersion = 0, lastSyncTimestamp = 0, deviceId = "local", vaultEpochId = newEpoch))
            }
            newEpoch
        }
    }

    suspend fun setVaultEpochId(epoch: String) = withContext(Dispatchers.IO) {
        if (epoch.isEmpty()) return@withContext
        val current = vaultMetadataDao.getMetadata()
        if (current != null) {
            vaultMetadataDao.updateMetadata(current.copy(vaultEpochId = epoch))
        } else {
            vaultMetadataDao.updateMetadata(VaultMetadata(vaultVersion = 0, lastSyncTimestamp = 0, deviceId = "local", vaultEpochId = epoch))
        }
    }

    suspend fun getLastKnownHmac(): String? = withContext(Dispatchers.IO) {
        vaultMetadataDao.getMetadata()?.lastKnownHmac
    }

    suspend fun updateVaultVersion(newVersion: Long, hmac: String? = null) = withContext(Dispatchers.IO) {
        val current = vaultMetadataDao.getMetadata()
        if (current != null) {
            vaultMetadataDao.updateMetadata(current.copy(
                vaultVersion = newVersion, 
                lastSyncTimestamp = System.currentTimeMillis(),
                lastKnownHmac = hmac ?: current.lastKnownHmac
            ))
        } else {
            vaultMetadataDao.updateMetadata(VaultMetadata(
                vaultVersion = newVersion, 
                lastSyncTimestamp = System.currentTimeMillis(), 
                deviceId = "local",
                lastKnownHmac = hmac
            ))
        }
    }

    suspend fun syncWithRemote(remoteEntities: List<PasswordEntity>) = withContext(Dispatchers.IO) {
        // Implement record-level synchronization
        val localEntities = passwordDao.getAllPasswordsList().associateBy { it.id }
        
        remoteEntities.forEach { remote: PasswordEntity ->
            val local = localEntities[remote.id]
            if (local == null || remote.lastModified > local.lastModified) {
                passwordDao.insertPassword(remote)
            }
        }
    }

    suspend fun savePassword(
        serviceName: String,
        username: String,
        password: String,
        notes: String? = null,
        id: Int? = null
    ): Long {
        val vaultKey = masterPasswordManager.getVaultKey()
            ?: throw IllegalStateException("Vault is locked")

        val existingEntity = id?.let { passwordDao.getPasswordById(it) }
        val createdAt = existingEntity?.createdAt ?: System.currentTimeMillis()
        val isFavorite = existingEntity?.isFavorite ?: false
        // recordUid is non-null in the entity now. Existing rows missing one were
        // backfilled by MIGRATION_5_6; new rows get a fresh UUID here.
        val recordUid = existingEntity?.recordUid?.takeIf { it.isNotBlank() }
            ?: java.util.UUID.randomUUID().toString()
        val encryptionVersion = 1
        val schemaVersion = 6
        val aad = "v$encryptionVersion|s$schemaVersion|$recordUid|$createdAt"
            .toByteArray(Charsets.UTF_8)

        val encService = encryptionManager.encryptWithKey(serviceName.toByteArray(), vaultKey, aad)
        val encUsername = encryptionManager.encryptWithKey(username.toByteArray(), vaultKey, aad)
        val encPassword = encryptionManager.encryptWithKey(password.toByteArray(), vaultKey, aad)
        val encNotes = notes?.let { encryptionManager.encryptWithKey(it.toByteArray(), vaultKey, aad) }

        val entity = PasswordEntity(
            id = id ?: 0,
            encryptedServiceName = android.util.Base64.encodeToString(encService.cipherText, android.util.Base64.NO_WRAP),
            serviceNameIv = android.util.Base64.encodeToString(encService.iv, android.util.Base64.NO_WRAP),
            encryptedUsername = android.util.Base64.encodeToString(encUsername.cipherText, android.util.Base64.NO_WRAP),
            usernameIv = android.util.Base64.encodeToString(encUsername.iv, android.util.Base64.NO_WRAP),
            encryptedPassword = android.util.Base64.encodeToString(encPassword.cipherText, android.util.Base64.NO_WRAP),
            passwordIv = android.util.Base64.encodeToString(encPassword.iv, android.util.Base64.NO_WRAP),
            encryptedNotes = encNotes?.let { android.util.Base64.encodeToString(it.cipherText, android.util.Base64.NO_WRAP) },
            notesIv = encNotes?.let { android.util.Base64.encodeToString(it.iv, android.util.Base64.NO_WRAP) },
            isFavorite = isFavorite,
            createdAt = createdAt,
            lastModified = System.currentTimeMillis(),
            recordUid = recordUid,
            encryptionVersion = encryptionVersion,
            schemaVersion = schemaVersion
        )

        return passwordDao.insertPassword(entity)
    }

    /**
     * Generates a new random Vault Key and re-encrypts all entries.
     * Safe order: read all plaintext with the OLD key, abort if any record is corrupt,
     * install the new key, then re-encrypt everything with the new key.
     */
    suspend fun rotateVaultKey(context: Context) = withContext(Dispatchers.IO) {
        masterPasswordManager.getVaultKey()
            ?: throw IllegalStateException("Vault must be unlocked")

        data class Plain(val id: Int, val service: String, val username: String, val password: String, val notes: String?)

        // 1. Materialize ALL plaintext using the CURRENT vault key first.
        val plaintext = getPasswords().map { item ->
            Plain(item.id, item.serviceName, item.username, item.password, item.notes)
        }

        // 2. Abort if any record failed to decrypt (never re-encrypt error placeholders).
        val corrupt = plaintext.any {
            it.service == "[Decryption Error]" || it.service == "[Vault Locked]" ||
            it.password == "[Decryption Error]" || it.password == "[Vault Locked]"
        }
        if (corrupt) throw IllegalStateException("Aborting rotation: some records could not be decrypted")

        // 3. Generate and install a NEW random 256-bit Vault Key.
        val rawNewKey = ByteArray(32)
        SecureRandom().nextBytes(rawNewKey)
        masterPasswordManager.installNewVaultKey(context, rawNewKey)
        rawNewKey.fill(0)

        // 4. Re-encrypt every record with the now-active new vault key.
        plaintext.forEach { rec ->
            savePassword(rec.service, rec.username, rec.password, rec.notes, rec.id)
        }

        // 5. Reset epoch for a clean cryptographic break.
        val newEpoch = java.util.UUID.randomUUID().toString()
        val current = vaultMetadataDao.getMetadata()
        if (current != null) {
            vaultMetadataDao.updateMetadata(current.copy(
                vaultEpochId = newEpoch,
                vaultVersion = 0,
                lastKnownHmac = null
            ))
        } else {
            vaultMetadataDao.updateMetadata(VaultMetadata(vaultVersion = 0, lastSyncTimestamp = 0, deviceId = "local", vaultEpochId = newEpoch))
        }
    }
}
