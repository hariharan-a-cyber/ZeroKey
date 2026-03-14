package com.hariharan.zerokey.data.database

import androidx.room.*

@Dao
interface VaultMetadataDao {
    @Query("SELECT * FROM vault_metadata WHERE id = 0")
    suspend fun getMetadata(): VaultMetadata?

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun updateMetadata(metadata: VaultMetadata)

    @Query("UPDATE vault_metadata SET vaultVersion = vaultVersion + 1 WHERE id = 0")
    suspend fun incrementVersion()
}
