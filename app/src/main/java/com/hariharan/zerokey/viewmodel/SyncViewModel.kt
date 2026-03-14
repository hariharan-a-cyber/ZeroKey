package com.hariharan.zerokey.viewmodel

import android.app.Application
import android.util.Base64
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.security.MasterPasswordManager
import com.hariharan.zerokey.security.SyncManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.crypto.SecretKey

/**
 * Handles the UI state and actions for cloud sync.
 */
class SyncViewModel(
    application: Application,
    private val syncManager: SyncManager
) : AndroidViewModel(application) {

    private val _syncState = MutableStateFlow<SyncState>(SyncState.Idle)
    val syncState = _syncState.asStateFlow()

    fun performSync(masterKey: SecretKey, hmacKey: SecretKey) {
        viewModelScope.launch {
            _syncState.value = SyncState.Syncing
            try {
                // Fetch the salt from MasterPasswordManager using application context
                val saltBytes = MasterPasswordManager.getSalt(getApplication())
                    ?: throw IllegalStateException("Vault salt not found. Please set up your vault first.")
                
                val saltString = Base64.encodeToString(saltBytes, Base64.NO_WRAP)

                // 1. Download and merge remote changes
                syncManager.downloadAndMergeVault(masterKey, hmacKey)
                
                // 2. Upload local changes with the required salt parameter
                syncManager.uploadEncryptedVault(masterKey, hmacKey, saltString)
                
                _syncState.value = SyncState.Success
            } catch (e: Exception) {
                _syncState.value = SyncState.Error(e.message ?: "Unknown sync error")
            }
        }
    }

    fun resetState() {
        _syncState.value = SyncState.Idle
    }

    sealed class SyncState {
        object Idle : SyncState()
        object Syncing : SyncState()
        object Success : SyncState()
        data class Error(val message: String) : SyncState()
    }
}
