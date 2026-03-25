package com.hariharan.zerokey.data.repository

import com.hariharan.zerokey.core.database.PasskeyEntity
import com.hariharan.zerokey.core.database.PasswordDao
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext

/**
 * Repository for managing Passkey records in the local database.
 */
class PasskeyRepository(private val passwordDao: PasswordDao) {

    fun getAllPasskeys(): Flow<List<PasskeyEntity>> {
        // Need to add this to PasswordDao if not present
        return passwordDao.getAllPasskeysFlow()
    }

    suspend fun savePasskey(passkey: PasskeyEntity) = withContext(Dispatchers.IO) {
        passwordDao.insertPasskey(passkey)
    }

    suspend fun deletePasskey(credentialId: String) = withContext(Dispatchers.IO) {
        passwordDao.deletePasskeyById(credentialId)
    }
}
