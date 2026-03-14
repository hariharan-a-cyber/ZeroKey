package com.hariharan.zerokey.data.database

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "vault_metadata")
data class VaultMetadata(
    @PrimaryKey val id: Int = 0,
    val vaultVersion: Long = 1,
    val lastSyncTimestamp: Long = 0,
    val deviceId: String
)
