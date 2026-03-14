package com.hariharan.zerokey.data.repository

import android.util.Base64
import com.hariharan.zerokey.data.database.PasswordDao
import com.hariharan.zerokey.data.database.PasswordEntity
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.security.EncryptedData
import com.hariharan.zerokey.security.EncryptionManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Phase 2: Vault Storage System.
 * Sole cleartext gateway. Handles all encryption/decryption before DB access.
 */
class PasswordRepository(private val passwordDao: PasswordDao) {

    suspend fun getPasswords(): List<PasswordItem> = withContext(Dispatchers.IO) {
        passwordDao.getAllPasswords().map { decryptEntity(it) }
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
        passwordDao.getPasswordById(id)?.let { decryptEntity(it) }
    }

    suspend fun updateFavorite(id: Int, isFavorite: Boolean) = withContext(Dispatchers.IO) {
        passwordDao.updateFavorite(id, isFavorite)
    }

    suspend fun savePassword(service: String, username: String, password: String, notes: String? = null) = withContext(Dispatchers.IO) {
        val item = PasswordItem(0, service, username, password, notes)
        passwordDao.insertPassword(encryptItem(item))
    }

    private fun encryptItem(item: PasswordItem): PasswordEntity {
        val serviceNameEnc = EncryptionManager.encrypt(item.serviceName.toByteArray())
        val usernameEnc = EncryptionManager.encrypt(item.username.toByteArray())
        val passwordEnc = EncryptionManager.encrypt(item.password.toByteArray())
        val notesEnc = item.notes?.let { EncryptionManager.encrypt(it.toByteArray()) }

        return PasswordEntity(
            id = item.id,
            encryptedServiceName = Base64.encodeToString(serviceNameEnc.cipherText, Base64.NO_WRAP),
            serviceNameIv = Base64.encodeToString(serviceNameEnc.iv, Base64.NO_WRAP),
            encryptedUsername = Base64.encodeToString(usernameEnc.cipherText, Base64.NO_WRAP),
            usernameIv = Base64.encodeToString(usernameEnc.iv, Base64.NO_WRAP),
            encryptedPassword = Base64.encodeToString(passwordEnc.cipherText, Base64.NO_WRAP),
            passwordIv = Base64.encodeToString(passwordEnc.iv, Base64.NO_WRAP),
            encryptedNotes = notesEnc?.let { Base64.encodeToString(it.cipherText, Base64.NO_WRAP) },
            notesIv = notesEnc?.let { Base64.encodeToString(it.iv, Base64.NO_WRAP) },
            isFavorite = item.isFavorite,
            lastModified = System.currentTimeMillis()
        )
    }

    private fun decryptEntity(entity: PasswordEntity): PasswordItem {
        val serviceName = EncryptionManager.decrypt(
            EncryptedData(Base64.decode(entity.encryptedServiceName, Base64.NO_WRAP), Base64.decode(entity.serviceNameIv, Base64.NO_WRAP))
        ).decodeToString()

        val username = EncryptionManager.decrypt(
            EncryptedData(Base64.decode(entity.encryptedUsername, Base64.NO_WRAP), Base64.decode(entity.usernameIv, Base64.NO_WRAP))
        ).decodeToString()

        val password = EncryptionManager.decrypt(
            EncryptedData(Base64.decode(entity.encryptedPassword, Base64.NO_WRAP), Base64.decode(entity.passwordIv, Base64.NO_WRAP))
        ).decodeToString()

        val notes = entity.encryptedNotes?.let {
            EncryptionManager.decrypt(
                EncryptedData(Base64.decode(it, Base64.NO_WRAP), Base64.decode(entity.notesIv!!, Base64.NO_WRAP))
            ).decodeToString()
        }

        return PasswordItem(
            id = entity.id,
            serviceName = serviceName,
            username = username,
            password = password,
            notes = notes,
            isFavorite = entity.isFavorite
        )
    }
}
