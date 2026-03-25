package com.hariharan.zerokey.domain.repository

import com.hariharan.zerokey.domain.model.VaultEntry
import kotlinx.coroutines.flow.Flow

interface VaultRepository {
    fun getVaultEntries(): Flow<List<VaultEntry>>
    suspend fun saveVaultEntry(entry: VaultEntry)
    suspend fun deleteVaultEntry(id: Int)
    suspend fun getVaultEntryById(id: Int): VaultEntry?
    suspend fun updateFavoriteStatus(id: Int, isFavorite: Boolean)
}
