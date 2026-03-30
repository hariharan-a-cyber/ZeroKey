package com.hariharan.zerokey.viewmodel

import android.content.Context
import android.util.Log
import android.widget.Toast
import androidx.compose.runtime.*
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.analytics.SecurityRecommendationEngine
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.data.database.AuditLogEntity
import com.hariharan.zerokey.data.database.PasswordEntity
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.security.*
import com.hariharan.zerokey.securityanalytics.VaultSecurityAnalyzer
import com.hariharan.zerokey.securityanalytics.PasswordEntropyAnalyzer
import com.hariharan.zerokey.securityanalytics.SecurityScoreCalculator
import com.hariharan.zerokey.securityanalytics.VaultSecurityReport
import com.hariharan.zerokey.sync.DeviceSyncManager
import com.hariharan.zerokey.sharing.CredentialShareManager
import com.hariharan.zerokey.emergency.EmergencyAccessManager
import com.hariharan.zerokey.utils.PasswordHealthAnalyzer
import com.hariharan.zerokey.utils.PasswordStrength
import com.hariharan.zerokey.utils.PasswordUtils
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import javax.crypto.spec.SecretKeySpec

class PasswordViewModel(
    private val repository: PasswordRepository,
    private val auditLogManager: AuditLogManager,
    private val backupManager: VaultBackupManager? = null,
    private val syncManager: DeviceSyncManager? = null,
    private val shareManager: CredentialShareManager? = null,
    private val emergencyManager: EmergencyAccessManager? = null,
    private val privacyModeManager: PrivacyModeManager? = null
) : ViewModel() {

    private val securityEventManager = SecurityEventManager(auditLogManager)
    private val securityAnalyzer = VaultSecurityAnalyzer(
        PasswordEntropyAnalyzer(),
        SecurityScoreCalculator(PasswordEntropyAnalyzer())
    )
    
    private var allPasswords = listOf<PasswordItem>()
    
    var passwords = mutableStateListOf<PasswordItem>()
        private set

    var searchQuery by mutableStateOf("")
        private set

    var auditLogs = mutableStateListOf<AuditLogEntity>()
        private set

    var healthReport by mutableStateOf(PasswordHealthAnalyzer.HealthReport(100, emptyList(), emptyList(), emptyList(), emptyList()))
        private set

    var securityReport by mutableStateOf<VaultSecurityReport?>(null)
        private set

    var recommendations = mutableStateListOf<SecurityRecommendationEngine.Recommendation>()
        private set

    var securityAlerts = mutableStateListOf<SecurityEventManager.SecurityAlert>()
        private set

    var isOfflineMode by mutableStateOf(privacyModeManager?.isOfflineOnly() ?: false)
        private set

    init {
        // Initial minimal load
        loadInitialData()
    }

    private fun loadInitialData() {
        viewModelScope.launch {
            // Load passwords first as they are critical for the main screen
            allPasswords = repository.getPasswords()
            filterPasswords()
            
            // Defer heavy calculations until after initial UI is ready
            launch(Dispatchers.Default) {
                healthReport = PasswordHealthAnalyzer.analyze(allPasswords)
                refreshSecurityInsights()
                
                // Defer security report as it's the heaviest and used in sub-screens
                updateSecurityReport()
            }
            
            // Load logs in background as they are for a separate screen
            launch {
                auditLogs.clear()
                auditLogs.addAll(auditLogManager.getLogs())
            }
        }
    }

    private suspend fun updateSecurityReport() {
        val vaultKey = MasterPasswordManager.getVaultKey()
        if (vaultKey != null) {
            val report = withContext(Dispatchers.Default) {
                securityAnalyzer.buildReport(allPasswords, vaultKey.encoded)
            }
            withContext(Dispatchers.Main) {
                securityReport = report
            }
        } else {
            withContext(Dispatchers.Main) {
                securityReport = VaultSecurityReport(0, emptyList(), emptyList(), emptyList(), emptyList())
            }
        }
    }

    fun loadPasswords() {
        viewModelScope.launch {
            allPasswords = repository.getPasswords()
            filterPasswords()
            
            // Trigger deferred updates
            launch(Dispatchers.Default) {
                healthReport = PasswordHealthAnalyzer.analyze(allPasswords)
                refreshSecurityInsights()
                updateSecurityReport()
            }
        }
    }

    private fun loadAuditLogs() {
        viewModelScope.launch {
            auditLogs.clear()
            auditLogs.addAll(auditLogManager.getLogs())
        }
    }

    fun refreshSecurityInsights() {
        viewModelScope.launch {
            val newRecommendations = SecurityRecommendationEngine.getRecommendations(healthReport)
            val newAlerts = securityEventManager.detectAnomalies()
            
            withContext(Dispatchers.Main) {
                recommendations.clear()
                recommendations.addAll(newRecommendations)
                securityAlerts.clear()
                securityAlerts.addAll(newAlerts)
            }
        }
    }

    fun toggleOfflineMode(context: Context, enabled: Boolean) {
        privacyModeManager?.setOfflineOnly(enabled)
        isOfflineMode = enabled
        
        val message = if (enabled) {
            "Stealth Protocol Activated: Vault is now air-gapped from all networks."
        } else {
            "Stealth Protocol Deactivated: Cloud features restored."
        }
        Toast.makeText(context, message, Toast.LENGTH_LONG).show()
    }

    fun syncVault(userId: String) {
        if (isOfflineMode || syncManager == null) return
        
        viewModelScope.launch {
            val vaultKey = MasterPasswordManager.getVaultKey()
            val hmacKey = vaultKey?.encoded ?: return@launch // Proper HMAC derivation needed in production
            
            if (vaultKey != null) {
                val entities = repository.getAllEntities()
                val vaultJson = Json.encodeToString(ListSerializer(PasswordEntity.serializer()), entities)
                syncManager.pushVaultSnapshot(userId, vaultJson, vaultKey.encoded, hmacKey)
            }
        }
    }

    fun onSearchQueryChange(query: String) {
        searchQuery = query
        filterPasswords()
    }

    private fun filterPasswords() {
        passwords.clear()
        if (searchQuery.isBlank()) {
            passwords.addAll(allPasswords)
        } else {
            val filtered = allPasswords.filter {
                it.serviceName.contains(searchQuery, ignoreCase = true) ||
                        it.username.contains(searchQuery, ignoreCase = true)
            }
            passwords.addAll(filtered)
        }
    }
    fun addPassword(
        service: String,
        username: String,
        password: String,
        notes: String? = null,
        onComplete: () -> Unit = {},
        onError: (String) -> Unit = {}   // ← new parameter
    ) {
        viewModelScope.launch {
            try {
                repository.savePassword(service, username, password, notes)
                auditLogManager.log(AuditLogManager.EventType.VAULT_UNLOCKED, "Added new password for $service")

                allPasswords = repository.getPasswords()
                filterPasswords()

                launch(Dispatchers.Default) {
                    healthReport = PasswordHealthAnalyzer.analyze(allPasswords)
                    refreshSecurityInsights()
                    updateSecurityReport()
                }

                withContext(Dispatchers.Main) {
                    onComplete()
                }
            } catch (e: IllegalStateException) {
                // Vault is locked — getVaultKey() returned null
                Log.e("PasswordViewModel", "Vault is locked, cannot save", e)
                withContext(Dispatchers.Main) {
                    onError("Session expired. Please lock and unlock the app again.")
                }
            } catch (e: Exception) {
                Log.e("PasswordViewModel", "Failed to add password", e)
                withContext(Dispatchers.Main) {
                    onError("Failed to save. Please try again.")
                }
            }
        }
    }

    fun deletePassword(item: PasswordItem) {
        viewModelScope.launch {
            repository.deletePassword(item.id)
            auditLogManager.log(AuditLogManager.EventType.VAULT_UNLOCKED, "Deleted password for ${item.serviceName}")
            loadPasswords()
            loadAuditLogs()
        }
    }

    fun isDuplicatePassword(password: String): Boolean {
        return allPasswords.any { it.password == password }
    }

    fun updateFavorite(item: PasswordItem, isFavorite: Boolean) {
        viewModelScope.launch {
            repository.updateFavorite(item.id, isFavorite)
            loadPasswords()
        }
    }

    fun logPasswordViewed(serviceName: String) {
        viewModelScope.launch {
            auditLogManager.log(AuditLogManager.EventType.PASSWORD_VIEWED, "Viewed password for $serviceName")
            loadAuditLogs()
        }
    }

    fun logPasswordCopied(serviceName: String) {
        viewModelScope.launch {
            auditLogManager.log(AuditLogManager.EventType.PASSWORD_COPIED, "Copied password for $serviceName")
            loadAuditLogs()
        }
    }

    fun exportVault(context: Context, file: File, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch {
            val vaultKey = MasterPasswordManager.getVaultKey()
            val salt = MasterPasswordManager.getSalt(context)?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
            
            if (vaultKey != null && salt != null && backupManager != null) {
                try {
                    backupManager.exportBackup(file, vaultKey, vaultKey, salt)
                    auditLogManager.log(AuditLogManager.EventType.VAULT_EXPORTED, "Vault exported to ${file.name}")
                    onComplete(true)
                } catch (e: Exception) {
                    onComplete(false)
                }
            } else {
                onComplete(false)
            }
        }
    }

    fun importVault(file: File, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch {
            val vaultKey = MasterPasswordManager.getVaultKey()
            if (vaultKey != null && backupManager != null) {
                try {
                    backupManager.importBackup(file, vaultKey, vaultKey)
                    auditLogManager.log(AuditLogManager.EventType.VAULT_UNLOCKED, "Vault imported from ${file.name}")
                    loadPasswords()
                    loadAuditLogs()
                    onComplete(true)
                } catch (e: Exception) {
                    onComplete(false)
                }
            } else {
                onComplete(false)
            }
        }
    }

    fun shareCredential(senderId: String, recipientId: String, credentialId: Int) {
        viewModelScope.launch {
            val item = allPasswords.find { it.id == credentialId } ?: return@launch
            val vaultKey = MasterPasswordManager.getVaultKey() ?: return@launch
            val hmacKey = vaultKey.encoded // Simplified
            
            val payload = Json.encodeToString(PasswordItem.serializer(), item)
            shareManager?.shareCredential(senderId, recipientId, payload, hmacKey)
            auditLogManager.log(AuditLogManager.EventType.PASSWORD_VIEWED, "Shared credential ${item.serviceName} with $recipientId")
        }
    }
}
