package com.hariharan.zerokey.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.security.MasterPasswordManager
import com.hariharan.zerokey.security.EncryptedData
import com.hariharan.zerokey.sync.DeviceSyncManager
import com.hariharan.zerokey.sync.PullResult
import com.hariharan.zerokey.sync.SyncResult
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.database.PasswordEntity
import com.hariharan.zerokey.utils.PrivacyLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer

class SyncViewModel(
    application: Application,
    private val repository: PasswordRepository,
    private val syncManager: DeviceSyncManager
) : AndroidViewModel(application) {

    private val _syncState = MutableStateFlow<SyncStatus>(SyncStatus.Idle)
    val syncState = _syncState.asStateFlow()

    fun performSync(userId: String) {
        viewModelScope.launch {
            _syncState.value = SyncStatus.Syncing
            
            try {
                val vaultKey = MasterPasswordManager.getVaultKey() 
                    ?: throw IllegalStateException("Vault is locked")
                
                val encryptionKey = vaultKey.encoded
                val hmacKey = vaultKey.encoded

                val localPasswords = repository.getPasswords()
                val localJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), localPasswords.map { it.toEntity() })
                val localVersion = repository.getVaultVersion()
                val localEpochId = repository.getVaultEpochId()
                val lastKnownHmac = repository.getLastKnownHmac()
                
                val pullResult = syncManager.pullVaultSnapshot(
                    userId = userId,
                    encryptionKey = encryptionKey,
                    hmacKey = hmacKey,
                    localVersion = localVersion,
                    localVaultJson = localJson,
                    localEpochId = localEpochId,
                    lastKnownHmac = lastKnownHmac
                )

                when (pullResult) {
                    is PullResult.Success -> {
                        val mergedEntities = Json.decodeFromString(ListSerializer(PasswordEntity.serializer()), pullResult.plaintextVault)
                        repository.syncWithRemote(mergedEntities)
                        repository.updateVaultVersion(pullResult.version, pullResult.snapshotHmac)
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
                            hmacKey = hmacKey,
                            wrappedKey = MasterPasswordManager.getWrappedVaultKey(),
                            vaultEpochId = localEpochId,
                            previousSnapshotHmac = null
                        )
                        if (pushResult is SyncResult.Success) {
                            repository.updateVaultVersion(pushResult.version, pushResult.snapshotHmac)
                            _syncState.value = SyncStatus.Success(System.currentTimeMillis())
                        } else {
                            handleSyncFailure((pushResult as SyncResult.Failure).reason)
                        }
                    }
                    is PullResult.IntegrityFailure -> {
                        val blob = pullResult.blob
                        if (blob?.wrappedVaultKey != null && blob.wrappedVaultKeyIv != null) {
                            try {
                                val wrapped = EncryptedData(
                                    cipherText = android.util.Base64.decode(blob.wrappedVaultKey, android.util.Base64.NO_WRAP),
                                    iv = android.util.Base64.decode(blob.wrappedVaultKeyIv, android.util.Base64.NO_WRAP)
                                )
                                MasterPasswordManager.importVaultKey(getApplication(), wrapped)
                                performSync(userId)
                                return@launch
                            } catch (e: Exception) {
                                PrivacyLogger.e("SyncViewModel", "Recovery failed: ${PrivacyLogger.sanitizeError(e.message)}")
                                _syncState.value = SyncStatus.Error("Vault integrity check failed", true)
                            }
                        } else {
                            _syncState.value = SyncStatus.Error("Vault integrity check failed", true)
                        }
                    }
                    is PullResult.Failure -> {
                        handleSyncFailure(pullResult.reason)
                    }
                }
            } catch (e: Exception) {
                PrivacyLogger.e("SyncViewModel", "Sync exception: ${PrivacyLogger.sanitizeError(e.message)}")
                _syncState.value = SyncStatus.Error("Sync failed due to a system error.")
            }
        }
    }

    private fun handleSyncFailure(reason: String) {
        PrivacyLogger.e("SyncViewModel", "Sync failed: ${PrivacyLogger.sanitizeError(reason)}")
        if (reason.contains("DEVICE_REVOKED", ignoreCase = true)) {
            MasterPasswordManager.lockVault()
            _syncState.value = SyncStatus.Error("Access Revoked: Device untrusted.", false)
        } else if (reason.contains("Rollback", ignoreCase = true) || 
                   reason.contains("Epoch", ignoreCase = true) || 
                   reason.contains("Chain", ignoreCase = true)) {
            _syncState.value = SyncStatus.Error(reason, true) // Allow manual fix/overwrite
        } else {
            val errorMsg = when {
                reason.contains("offline", ignoreCase = true) -> "Sync failed: Firestore is offline."
                reason.contains("permission-denied", ignoreCase = true) -> "Sync failed: Check Firebase rules."
                else -> "Sync failed."
            }
            _syncState.value = SyncStatus.Error(errorMsg)
        }
    }

    sealed class SyncStatus {
        object Idle : SyncStatus()
        object Syncing : SyncStatus()
        data class Success(val lastSync: Long) : SyncStatus()
        data class Error(val message: String, val canReset: Boolean = false) : SyncStatus()
    }

    fun forceResetCloudVault(userId: String) {
        viewModelScope.launch {
            _syncState.value = SyncStatus.Syncing
            try {
                val vaultKey = MasterPasswordManager.getVaultKey() ?: throw IllegalStateException("Vault is locked")
                val localPasswords = repository.getPasswords()
                val localJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), localPasswords.map { it.toEntity() })
                
                val pushResult = syncManager.pushVaultSnapshot(
                    userId = userId,
                    plaintextVaultJson = localJson,
                    encryptionKey = vaultKey.encoded,
                    hmacKey = vaultKey.encoded,
                    wrappedKey = MasterPasswordManager.getWrappedVaultKey(),
                    vaultEpochId = repository.getVaultEpochId(),
                    previousSnapshotHmac = repository.getLastKnownHmac()
                )

                if (pushResult is SyncResult.Success) {
                    repository.updateVaultVersion(pushResult.version, pushResult.snapshotHmac)
                    _syncState.value = SyncStatus.Success(System.currentTimeMillis())
                } else {
                    handleSyncFailure((pushResult as SyncResult.Failure).reason)
                }
            } catch (e: Exception) {
                _syncState.value = SyncStatus.Error("Reset error")
            }
        }
    }
}
