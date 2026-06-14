package com.hariharan.zerokey.core.database

import androidx.room.*
import kotlinx.coroutines.flow.Flow

@Dao
interface PasswordDao {

    // --- Passwords ---
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

    // --- Passkeys ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPasskey(passkey: PasskeyEntity)

    @Query("SELECT * FROM passkey_records")
    fun getAllPasskeysFlow(): Flow<List<PasskeyEntity>>

    @Query("DELETE FROM passkey_records WHERE credentialId = :credentialId")
    suspend fun deletePasskeyById(credentialId: String)

    // --- Security Events ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSecurityEvent(event: SecurityEventEntity)

    @Query("SELECT * FROM security_events ORDER BY timestamp DESC")
    fun getAllSecurityEventsFlow(): Flow<List<SecurityEventEntity>>

    // --- Incoming Shares ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSharedCredential(share: SharedCredentialEntity)

    @Query("SELECT * FROM incoming_shares WHERE status = :status")
    fun getSharedCredentialsByStatusFlow(status: String): Flow<List<SharedCredentialEntity>>

    // --- Emergency Access ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertEmergencyConfig(config: EmergencyAccessEntity)

    @Query("SELECT * FROM emergency_access_config WHERE ownerId = :ownerId")
    suspend fun getEmergencyConfig(ownerId: String): EmergencyAccessEntity?

    // --- Sync Metadata ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSyncMetadata(metadata: SyncMetadataEntity)

    @Query("SELECT * FROM vault_sync_metadata WHERE userId = :userId")
    suspend fun getSyncMetadata(userId: String): SyncMetadataEntity?
}
