package com.hariharan.zerokey.data.repository

import android.util.Base64
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.database.PasswordDao
import com.hariharan.zerokey.core.database.PasswordEntity
import com.hariharan.zerokey.domain.model.VaultEntry
import com.hariharan.zerokey.domain.repository.VaultRepository
import com.hariharan.zerokey.core.security.MasterPasswordManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext

class VaultRepositoryImpl(
    private val passwordDao: PasswordDao
) : VaultRepository {

    override fun getVaultEntries(): Flow<List<VaultEntry>> {
        return passwordDao.getAllPasswordsFlow().map { entities ->
            entities.map { decryptEntity(it) }
        }
    }

    override suspend fun getVaultEntryById(id: Int): VaultEntry? = withContext(Dispatchers.IO) {
        passwordDao.getPasswordById(id)?.let { decryptEntity(it) }
    }

    override suspend fun saveVaultEntry(entry: VaultEntry) = withContext(Dispatchers.IO) {
        passwordDao.insertPassword(encryptEntry(entry))
    }

    override suspend fun deleteVaultEntry(id: Int) = withContext(Dispatchers.IO) {
        passwordDao.deletePasswordById(id)
    }

    override suspend fun updateFavoriteStatus(id: Int, isFavorite: Boolean) = withContext(Dispatchers.IO) {
        passwordDao.updateFavorite(id, isFavorite)
    }

    private fun encryptEntry(entry: VaultEntry): PasswordEntity {
        val vaultKey = MasterPasswordManager.getVaultKey()
            ?: throw IllegalStateException("Vault is locked")

        val aad = "timestamp:${entry.createdAt}".toByteArray()

        // Convert CharArray to ByteArray for encryption
        val passwordBytes = entry.password.map { it.code.toByte() }.toByteArray()
        
        val serviceNameEnc = EncryptionManager.encryptWithKey(entry.serviceName.toByteArray(), vaultKey, aad)
        val usernameEnc = EncryptionManager.encryptWithKey(entry.username.toByteArray(), vaultKey, aad)
        val passwordEnc = EncryptionManager.encryptWithKey(passwordBytes, vaultKey, aad)
        val notesEnc = entry.notes?.let { EncryptionManager.encryptWithKey(it.toByteArray(), vaultKey, aad) }

        // Wipe temporary byte array
        passwordBytes.fill(0)

        return PasswordEntity(
            id = entry.id,
            encryptedServiceName = Base64.encodeToString(serviceNameEnc.cipherText, Base64.NO_WRAP),
            serviceNameIv = Base64.encodeToString(serviceNameEnc.iv, Base64.NO_WRAP),
            encryptedUsername = Base64.encodeToString(usernameEnc.cipherText, Base64.NO_WRAP),
            usernameIv = Base64.encodeToString(usernameEnc.iv, Base64.NO_WRAP),
            encryptedPassword = Base64.encodeToString(passwordEnc.cipherText, Base64.NO_WRAP),
            passwordIv = Base64.encodeToString(passwordEnc.iv, Base64.NO_WRAP),
            encryptedNotes = notesEnc?.let { Base64.encodeToString(it.cipherText, Base64.NO_WRAP) },
            notesIv = notesEnc?.let { Base64.encodeToString(it.iv, Base64.NO_WRAP) },
            isFavorite = entry.isFavorite,
            createdAt = entry.createdAt,
            lastModified = System.currentTimeMillis()
        )
    }

    private fun decryptEntity(entity: PasswordEntity): VaultEntry {
        val vaultKey = MasterPasswordManager.getVaultKey()
            ?: throw IllegalStateException("Vault is locked")

        val aad = "timestamp:${entity.createdAt}".toByteArray()

        val serviceName = EncryptionManager.decryptWithKey(
            EncryptedData(Base64.decode(entity.encryptedServiceName, Base64.NO_WRAP), Base64.decode(entity.serviceNameIv, Base64.NO_WRAP)),
            vaultKey,
            aad
        ).decodeToString()

        val username = EncryptionManager.decryptWithKey(
            EncryptedData(Base64.decode(entity.encryptedUsername, Base64.NO_WRAP), Base64.decode(entity.usernameIv, Base64.NO_WRAP)),
            vaultKey,
            aad
        ).decodeToString()

        val passwordBytes = EncryptionManager.decryptWithKey(
            EncryptedData(Base64.decode(entity.encryptedPassword, Base64.NO_WRAP), Base64.decode(entity.passwordIv, Base64.NO_WRAP)),
            vaultKey,
            aad
        )
        
        val password = passwordBytes.map { it.toInt().toChar() }.toCharArray()
        passwordBytes.fill(0)

        val notes = entity.encryptedNotes?.let {
            EncryptionManager.decryptWithKey(
                EncryptedData(Base64.decode(it, Base64.NO_WRAP), Base64.decode(entity.notesIv!!, Base64.NO_WRAP)),
                vaultKey,
                aad
            ).decodeToString()
        }

        return VaultEntry(
            id = entity.id,
            serviceName = serviceName,
            username = username,
            password = password,
            notes = notes,
            isFavorite = entity.isFavorite,
            createdAt = entity.createdAt,
            lastModified = entity.lastModified
        )
    }
}
