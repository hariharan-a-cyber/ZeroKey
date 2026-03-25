package com.hariharan.zerokey.data.repository

import android.util.Base64
import com.hariharan.zerokey.data.database.PasswordDao
import com.hariharan.zerokey.data.database.PasswordEntity
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.security.EncryptedData
import com.hariharan.zerokey.security.EncryptionManager
import com.hariharan.zerokey.security.MasterPasswordManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Phase 2: Vault Storage System.
 * Sole cleartext gateway. Handles all encryption/decryption before DB access.
 * Refactored to use Envelope Encryption and Associated Authenticated Data (AAD).
 * Performance: Uses Lazy Decryption via PasswordItem.
 */
class PasswordRepository(private val passwordDao: PasswordDao) {

    suspend fun getPasswords(): List<PasswordItem> = withContext(Dispatchers.IO) {
        passwordDao.getAllPasswords().map { PasswordItem(id = it.id, encryptedEntity = it, isFavorite = it.isFavorite) }
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
        passwordDao.getPasswordById(id)?.let { PasswordItem(id = it.id, encryptedEntity = it, isFavorite = it.isFavorite) }
    }

    suspend fun updateFavorite(id: Int, isFavorite: Boolean) = withContext(Dispatchers.IO) {
        passwordDao.updateFavorite(id, isFavorite)
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

    suspend fun savePassword(service: String, username: String, password: String, notes: String? = null) = withContext(Dispatchers.IO) {
        val vaultKey = MasterPasswordManager.getVaultKey() 
            ?: throw IllegalStateException("Vault must be unlocked before saving passwords")

        val createdAt = System.currentTimeMillis()
        val aad = "timestamp:$createdAt".toByteArray()

        val serviceNameEnc = EncryptionManager.encryptWithKey(service.toByteArray(), vaultKey, aad)
        val usernameEnc = EncryptionManager.encryptWithKey(username.toByteArray(), vaultKey, aad)
        val passwordEnc = EncryptionManager.encryptWithKey(password.toByteArray(), vaultKey, aad)
        val notesEnc = notes?.let { EncryptionManager.encryptWithKey(it.toByteArray(), vaultKey, aad) }

        val entity = PasswordEntity(
            id = 0,
            encryptedServiceName = Base64.encodeToString(serviceNameEnc.cipherText, Base64.NO_WRAP),
            serviceNameIv = Base64.encodeToString(serviceNameEnc.iv, Base64.NO_WRAP),
            encryptedUsername = Base64.encodeToString(usernameEnc.cipherText, Base64.NO_WRAP),
            usernameIv = Base64.encodeToString(usernameEnc.iv, Base64.NO_WRAP),
            encryptedPassword = Base64.encodeToString(passwordEnc.cipherText, Base64.NO_WRAP),
            passwordIv = Base64.encodeToString(passwordEnc.iv, Base64.NO_WRAP),
            encryptedNotes = notesEnc?.let { Base64.encodeToString(it.cipherText, Base64.NO_WRAP) },
            notesIv = notesEnc?.let { Base64.encodeToString(it.iv, Base64.NO_WRAP) },
            isFavorite = false,
            createdAt = createdAt,
            lastModified = System.currentTimeMillis()
        )
        passwordDao.insertPassword(entity)
    }
}
