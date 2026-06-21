package com.hariharan.zerokey.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.core.security.MasterPasswordManager
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.HmacEngine
import com.hariharan.zerokey.security.FeatureAccessManager
import com.hariharan.zerokey.security.PrivacyModeManager
import com.hariharan.zerokey.sync.DeviceSyncManager
import com.hariharan.zerokey.sync.PullResult
import com.hariharan.zerokey.sync.SyncResult
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.core.database.PasswordEntity
import com.hariharan.zerokey.core.common.PrivacyLogger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer

import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class SyncViewModel @Inject constructor(
    application: android.app.Application,
    private val repository: PasswordRepository,
    private val syncManager: DeviceSyncManager,
    private val masterPasswordManager: MasterPasswordManager,
    private val hmacEngine: HmacEngine,
    private val featureAccessManager: FeatureAccessManager,
    private val privacyModeManager: PrivacyModeManager
) : AndroidViewModel(application) {

    private val _syncState = MutableStateFlow<SyncStatus>(SyncStatus.Idle)
    val syncState = _syncState.asStateFlow()

    fun performSync(userId: String) {
        viewModelScope.launch {
            if (!featureAccessManager.hasAccess(FeatureAccessManager.Feature.CLOUD_SYNC)) {
                _syncState.value = SyncStatus.Error("Cloud Sync requires an active subscription.")
                return@launch
            }
            if (privacyModeManager.isOfflineOnly()) {
                _syncState.value = SyncStatus.Error("Offline (Stealth) mode is ON. Turn it off in the vault menu to sync.")
                return@launch
            }
            _syncState.value = SyncStatus.Syncing

            val vaultKey = masterPasswordManager.getVaultKey()
            if (vaultKey == null) {
                val message = if (masterPasswordManager.isUnlocked()) "Session integrity error. Please lock and unlock." 
                              else "Vault locked due to inactivity. Please unlock to sync."
                _syncState.value = SyncStatus.Error(message)
                return@launch
            }

            if (!masterPasswordManager.isFullUnlock()) {
                PrivacyLogger.i("SyncViewModel", "Partial unlock detected (Biometric). Proceeding with vault update only.")
            }

            val encKeyBytes = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-enc-v1")
            val macKeyBytes = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-mac-v1")

            try {
                // Adapting provided logic to existing pullVaultSnapshot signature and results.
                val localPasswords = repository.getPasswords()
                val localJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), localPasswords.map { it.toEntity() })
                val localVersion = repository.getVaultVersion()
                val localEpochId = repository.getVaultEpochId()
                val lastKnownHmac = repository.getLastKnownHmac()

                val pullResult = syncManager.pullVaultSnapshot(
                    userId = userId,
                    encryptionKey = encKeyBytes,
                    hmacKey = macKeyBytes,
                    localVersion = localVersion,
                    localVaultJson = localJson,
                    localEpochId = localEpochId,
                    lastKnownHmac = lastKnownHmac
                )

                when (pullResult) {
                    is PullResult.Success -> {
                        val mergedEntities = Json.decodeFromString(ListSerializer(PasswordEntity.serializer()), pullResult.plaintextVault)
                        repository.syncWithRemote(mergedEntities)
                        repository.setVaultEpochId(pullResult.epochId)
                        // CRITICAL: Update local metadata with remote values after pull
                        // to ensure the next push references the correct previous state.
                        repository.updateVaultVersion(pullResult.version, pullResult.snapshotHmac)
                    }
                    is PullResult.NoRemoteVault -> {
                        // First-time sync — nothing to pull. Just push.
                    }
                    is PullResult.IntegrityFailure -> {
                        // SECURITY: do NOT silently re-import a vault key on integrity
                        // failure. A malicious/replayed remote could roll back the
                        // local vault. Stop sync and surface the error.
                        PrivacyLogger.e(
                            "SyncViewModel",
                            "Vault HMAC mismatch — refusing automatic recovery"
                        )
                        _syncState.value = SyncStatus.Error(
                            "Vault integrity check failed. Sync was stopped to protect your data. " +
                                "If you trust the remote vault, use 'Overwrite Cloud Vault' to reset.",
                            true
                        )
                        return@launch
                    }
                    is PullResult.Failure -> {
                        _syncState.value = SyncStatus.Error(pullResult.reason)
                        return@launch
                    }
                    else -> {
                        // Handle other cases like Conflict if they still exist
                        _syncState.value = SyncStatus.Error("Sync interrupted")
                        return@launch
                    }
                }

                val entities = repository.getAllEntities()
                val mergedJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), entities)
                
                // SECURITY: Only update the wrapped vault key if we have the master key in memory
                // (Full Unlock). If on biometric, masterPasswordManager.getWrappedVaultKey() 
                // returns null, which our SyncModels.toMap() handles by OMITTING the field,
                // thus preserving the existing one in Firestore via SetOptions.merge().
                val wrappedKey = masterPasswordManager.getWrappedVaultKey()
                if (wrappedKey == null && masterPasswordManager.isUnlocked()) {
                    PrivacyLogger.i("SyncViewModel", "Biometric session: preserving existing server-side recovery wrapper.")
                }

                val pushResult = syncManager.pushVaultSnapshot(
                    userId = userId,
                    plaintextVaultJson = mergedJson,
                    encryptionKey = encKeyBytes,
                    hmacKey = macKeyBytes,
                    wrappedKey = wrappedKey,
                    vaultEpochId = repository.getVaultEpochId(),
                    previousSnapshotHmac = repository.getLastKnownHmac()
                )

                if (pushResult is SyncResult.Success) {
                    repository.updateVaultVersion(pushResult.version, pushResult.snapshotHmac)
                    
                    // Proactive Check: Ensure cloud has the master key wrapper and salt
                    // This allows new devices to restore the vault using just the password.
                    if (masterPasswordManager.isFullUnlock()) {
                        val salt = masterPasswordManager.getSalt(getApplication())
                        if (salt != null) {
                            com.google.firebase.firestore.FirebaseFirestore.getInstance()
                                .collection("users").document(userId).set(
                                    mapOf(
                                        "vault_salt" to android.util.Base64.encodeToString(salt, android.util.Base64.NO_WRAP),
                                        "crypto_version" to masterPasswordManager.getCryptoVersion(getApplication(), userId)
                                    ),
                                    com.google.firebase.firestore.SetOptions.merge()
                                )
                        }
                    }
                    
                    _syncState.value = SyncStatus.Success(System.currentTimeMillis())
                } else {
                    handleSyncFailure((pushResult as SyncResult.Failure).reason)
                }
            } catch (e: Exception) {
                PrivacyLogger.e("SyncViewModel", "Sync failed: ${PrivacyLogger.sanitizeError(e.message)}")
                _syncState.value = SyncStatus.Error("Sync failed.")
            } finally {
                encKeyBytes.fill(0)
                macKeyBytes.fill(0)
            }
        }
    }

    private fun handleSyncFailure(reason: String) {
        PrivacyLogger.e("SyncViewModel", "Sync failed: ${PrivacyLogger.sanitizeError(reason)}")
        if (reason.contains("DEVICE_REVOKED", ignoreCase = true)) {
            masterPasswordManager.lockVault()
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
                val vaultKey = masterPasswordManager.getVaultKey() ?: throw IllegalStateException("Vault is locked")
                val localPasswords = repository.getPasswords()
                val localJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), localPasswords.map { it.toEntity() })
                
                val pushResult = syncManager.pushVaultSnapshot(
                    userId = userId,
                    plaintextVaultJson = localJson,
                    encryptionKey = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-enc-v1"),
                    hmacKey = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-mac-v1"),
                    wrappedKey = masterPasswordManager.getWrappedVaultKey(),
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
