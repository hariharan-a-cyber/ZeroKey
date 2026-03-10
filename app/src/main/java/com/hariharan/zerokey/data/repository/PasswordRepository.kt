package com.hariharan.zerokey.data.repository

import android.util.Base64
import com.hariharan.zerokey.data.database.PasswordDao
import com.hariharan.zerokey.data.database.PasswordEntity
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.security.EncryptedData
import com.hariharan.zerokey.security.EncryptionManager

/**
 * Production-Grade PasswordRepository.
 * Encrypts ALL metadata to prevent data leaks from a compromised database.
 */
class PasswordRepository(
    private val passwordDao: PasswordDao,
    private val encryptionManager: EncryptionManager
) {

    suspend fun savePassword(
        serviceName: String,
        username: String,
        password: String,
        notes: String?,
        isFavorite: Boolean = false
    ) {
        // Encrypt all fields individually
        val encService = encryptionManager.encrypt(serviceName)
        val encUser = encryptionManager.encrypt(username)
        val encPass = encryptionManager.encrypt(password)
        val encNotes = notes?.let { encryptionManager.encrypt(it) }

        val entity = PasswordEntity(
            encryptedServiceName = Base64.encodeToString(encService.cipherText, Base64.DEFAULT),
            serviceNameIv = Base64.encodeToString(encService.iv, Base64.DEFAULT),
            encryptedUsername = Base64.encodeToString(encUser.cipherText, Base64.DEFAULT),
            usernameIv = Base64.encodeToString(encUser.iv, Base64.DEFAULT),
            encryptedPassword = Base64.encodeToString(encPass.cipherText, Base64.DEFAULT),
            passwordIv = Base64.encodeToString(encPass.iv, Base64.DEFAULT),
            encryptedNotes = encNotes?.let { Base64.encodeToString(it.cipherText, Base64.DEFAULT) },
            notesIv = encNotes?.let { Base64.encodeToString(it.iv, Base64.DEFAULT) },
            isFavorite = isFavorite
        )

        passwordDao.insertPassword(entity)
    }

    suspend fun getPasswords(): List<PasswordItem> {
        return passwordDao.getAllPasswords().map { entity ->
            // Decrypt all fields individually
            val serviceName = encryptionManager.decrypt(
                EncryptedData(Base64.decode(entity.encryptedServiceName, Base64.DEFAULT), Base64.decode(entity.serviceNameIv, Base64.DEFAULT))
            )
            val username = encryptionManager.decrypt(
                EncryptedData(Base64.decode(entity.encryptedUsername, Base64.DEFAULT), Base64.decode(entity.usernameIv, Base64.DEFAULT))
            )
            val password = encryptionManager.decrypt(
                EncryptedData(Base64.decode(entity.encryptedPassword, Base64.DEFAULT), Base64.decode(entity.passwordIv, Base64.DEFAULT))
            )
            val notes = entity.encryptedNotes?.let {
                encryptionManager.decrypt(
                    EncryptedData(Base64.decode(it, Base64.DEFAULT), Base64.decode(entity.notesIv!!, Base64.DEFAULT))
                )
            }

            PasswordItem(
                id = entity.id,
                serviceName = serviceName,
                username = username,
                password = password,
                notes = notes,
                isFavorite = entity.isFavorite
            )
        }
    }

    suspend fun updateFavorite(id: Int, isFavorite: Boolean) {
        passwordDao.updateFavoriteStatus(id, isFavorite)
    }

    suspend fun deletePassword(id: Int) {
        passwordDao.deletePasswordById(id)
    }
}
