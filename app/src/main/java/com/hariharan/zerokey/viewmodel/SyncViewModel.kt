package com.hariharan.zerokey.viewmodel

import android.util.Log
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.security.MasterPasswordManager
import com.hariharan.zerokey.sync.DeviceSyncManager
import com.hariharan.zerokey.sync.PullResult
import com.hariharan.zerokey.sync.SyncResult
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.database.PasswordEntity
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer

class SyncViewModel(
    private val repository: PasswordRepository,
    private val syncManager: DeviceSyncManager
) : ViewModel() {

    private val _syncState = MutableStateFlow<SyncStatus>(SyncStatus.Idle)
    val syncState = _syncState.asStateFlow()

    fun performSync(userId: String) {
        viewModelScope.launch {
            _syncState.value = SyncStatus.Syncing
            
            try {
                val vaultKey = MasterPasswordManager.getVaultKey() 
                    ?: throw IllegalStateException("Vault is locked")
                
                // For simplicity in this implementation, we use the vault key's bytes as both encryption and HMAC keys
                // In a production app, these would be derived separately from the master key.
                val encryptionKey = vaultKey.encoded
                val hmacKey = vaultKey.encoded

                // 1. Pull and Merge
                val localPasswords = repository.getPasswords()
                val localJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), localPasswords.map { it.toEntity() })
                
                val pullResult = syncManager.pullVaultSnapshot(
                    userId = userId,
                    encryptionKey = encryptionKey,
                    hmacKey = hmacKey,
                    localVersion = 0,
                    localVaultJson = localJson
                )

                when (pullResult) {
                    is PullResult.Success -> {
                        val mergedEntities = Json.decodeFromString(ListSerializer(PasswordEntity.serializer()), pullResult.plaintextVault)
                        repository.syncWithRemote(mergedEntities)
                        _syncState.value = SyncStatus.Success(System.currentTimeMillis())
                    }
                    is PullResult.Conflict -> {
                        val mergedEntities = Json.decodeFromString(ListSerializer(PasswordEntity.serializer()), pullResult.resolvedVault)
                        repository.syncWithRemote(mergedEntities)
                        _syncState.value = SyncStatus.Success(System.currentTimeMillis())
                    }
                    is PullResult.NoRemoteVault -> {
                        val pushResult = syncManager.pushVaultSnapshot(
                            userId = userId,
                            plaintextVaultJson = localJson,
                            encryptionKey = encryptionKey,
                            hmacKey = hmacKey
                        )
                        if (pushResult is SyncResult.Success) {
                            _syncState.value = SyncStatus.Success(System.currentTimeMillis())
                        } else {
                            _syncState.value = SyncStatus.Error("Initial push failed")
                        }
                    }
                    is PullResult.IntegrityFailure -> _syncState.value = SyncStatus.Error("Vault integrity check failed (Security Alert)")
                    is PullResult.Failure -> _syncState.value = SyncStatus.Error(pullResult.reason)
                }
            } catch (e: Exception) {
                Log.e("SyncViewModel", "Sync failed", e)
                _syncState.value = SyncStatus.Error(e.message ?: "Unknown error")
            }
        }
    }

    sealed class SyncStatus {
        object Idle : SyncStatus()
        object Syncing : SyncStatus()
        data class Success(val lastSync: Long) : SyncStatus()
        data class Error(val message: String) : SyncStatus()
    }
}
