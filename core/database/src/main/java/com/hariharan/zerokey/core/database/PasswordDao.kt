package com.hariharan.zerokey.core.database

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface PasswordDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPassword(password: PasswordEntity)

    @Query("SELECT * FROM passwords")
    suspend fun getAllPasswords(): List<PasswordEntity>

    @Query("SELECT * FROM passwords")
    fun getAllPasswordsFlow(): Flow<List<PasswordEntity>>

    @Query("SELECT * FROM passwords WHERE id = :id")
    suspend fun getPasswordById(id: Int): PasswordEntity?

    @Query("DELETE FROM passwords WHERE id = :id")
    suspend fun deletePasswordById(id: Int)

    @Update
    suspend fun updatePassword(password: PasswordEntity)

    @Query("UPDATE passwords SET isFavorite = :isFavorite WHERE id = :id")
    suspend fun updateFavorite(id: Int, isFavorite: Boolean)

    @Delete
    suspend fun deletePassword(password: PasswordEntity)

    // Passkey methods
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPasskey(passkey: PasskeyEntity)

    @Query("SELECT * FROM passkey_records")
    fun getAllPasskeysFlow(): Flow<List<PasskeyEntity>>

    @Query("DELETE FROM passkey_records WHERE credentialId = :credentialId")
    suspend fun deletePasskeyById(credentialId: String)
}
