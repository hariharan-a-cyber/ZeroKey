package com.hariharan.zerokey.viewmodel

import android.content.Context
import androidx.compose.runtime.*
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.analytics.SecurityRecommendationEngine
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.data.database.AuditLogEntity
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
import kotlinx.coroutines.launch
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
        loadPasswords()
        loadAuditLogs()
        refreshSecurityInsights()
    }

    fun loadPasswords() {
        viewModelScope.launch {
            allPasswords = repository.getPasswords()
            filterPasswords()
            healthReport = PasswordHealthAnalyzer.analyze(allPasswords)
            
            // Comprehensive Security Analysis
            val masterKey = MasterPasswordManager.getSessionKey()
            if (masterKey != null) {
                securityReport = securityAnalyzer.buildReport(allPasswords, masterKey.encoded)
            }
            
            refreshSecurityInsights()
        }
    }

    private fun loadAuditLogs() {
        viewModelScope.launch {
            auditLogs.clear()
            auditLogs.addAll(auditLogManager.getLogs())
            refreshSecurityInsights()
        }
    }

    fun refreshSecurityInsights() {
        viewModelScope.launch {
            recommendations.clear()
            recommendations.addAll(SecurityRecommendationEngine.getRecommendations(healthReport))
            
            securityAlerts.clear()
            securityAlerts.addAll(securityEventManager.detectAnomalies())
        }
    }

    fun toggleOfflineMode(enabled: Boolean) {
        privacyModeManager?.setOfflineOnly(enabled)
        isOfflineMode = enabled
    }

    fun syncVault(userId: String) {
        if (isOfflineMode || syncManager == null) return
        
        viewModelScope.launch {
            val masterKey = MasterPasswordManager.getSessionKey()
            if (masterKey != null) {
                // In a real implementation, we would handle JSON serialization of all entities
                // syncManager.pushVault(userId, vaultJson, masterKey.encoded, masterKey.encoded)
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

    fun addPassword(service: String, username: String, password: String, notes: String? = null) {
        viewModelScope.launch {
            repository.savePassword(service, username, password, notes)
            auditLogManager.log(AuditLogManager.EventType.VAULT_UNLOCKED, "Added new password for $service")
            loadPasswords()
            loadAuditLogs()
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
            val masterKey = MasterPasswordManager.getSessionKey()
            val salt = MasterPasswordManager.getSalt(context)?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
            
            if (masterKey != null && salt != null && backupManager != null) {
                try {
                    backupManager.exportBackup(file, masterKey, masterKey, salt)
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
            val masterKey = MasterPasswordManager.getSessionKey()
            if (masterKey != null && backupManager != null) {
                try {
                    backupManager.importBackup(file, masterKey, masterKey)
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
}
