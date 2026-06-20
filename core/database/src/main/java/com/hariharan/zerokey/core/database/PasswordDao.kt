package com.hariharan.zerokey.core.database

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import kotlinx.coroutines.flow.Flow

@Dao
interface PasswordDao {

    // --- Passwords ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertPassword(password: PasswordEntity): Long

    @Update
    suspend fun update(password: PasswordEntity)

    @Query("SELECT * FROM passwords WHERE id = :id")
    suspend fun getPasswordById(id: Int): PasswordEntity?

    @Query("SELECT * FROM passwords WHERE recordUid = :uid LIMIT 1")
    suspend fun getPasswordByRecordUid(uid: String): PasswordEntity?

    @Query("SELECT * FROM passwords ORDER BY isFavorite DESC, lastModified DESC")
    fun getAllPasswords(): Flow<List<PasswordEntity>>

    @Query("SELECT * FROM passwords ORDER BY lastModified DESC")
    suspend fun getAllPasswordsList(): List<PasswordEntity>

    @Query("DELETE FROM passwords WHERE id = :id")
    suspend fun deletePasswordById(id: Int)

    @Delete
    suspend fun deletePassword(password: PasswordEntity)

    @Query("DELETE FROM passwords")
    suspend fun deleteAllPasswords()

    @Query("UPDATE passwords SET isFavorite = :isFavorite WHERE id = :id")
    suspend fun updateFavorite(id: Int, isFavorite: Boolean)

    // --- Sync Metadata ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSyncMetadata(metadata: SyncMetadataEntity)

    @Query("SELECT * FROM vault_sync_metadata WHERE userId = :userId")
    suspend fun getSyncMetadata(userId: String): SyncMetadataEntity?

    // --- Shared Credentials (Incoming) ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSharedCredential(share: SharedCredentialEntity)

    @Query("SELECT * FROM incoming_shares WHERE status = :status")
    fun getSharedCredentialsByStatusFlow(status: String): Flow<List<SharedCredentialEntity>>

    // --- Security Score History ---
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertSecurityScore(record: SecurityScoreHistoryEntity)

    @Query("SELECT * FROM security_score_history WHERE userId = :userId ORDER BY recordedAt DESC LIMIT 30")
    suspend fun getRecentSecurityScores(userId: String): List<SecurityScoreHistoryEntity>
}
