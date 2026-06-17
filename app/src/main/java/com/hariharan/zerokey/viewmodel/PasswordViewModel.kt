package com.hariharan.zerokey.viewmodel

import android.content.Context
import com.hariharan.zerokey.core.common.PrivacyLogger
import android.widget.Toast
import androidx.compose.runtime.*
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hariharan.zerokey.analytics.SecurityRecommendationEngine
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.core.database.AuditLogEntity
import com.hariharan.zerokey.core.database.PasswordEntity
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.core.security.MasterPasswordManager
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
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.security.BreachMonitor
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject

@HiltViewModel
class PasswordViewModel @Inject constructor(
    private val repository: PasswordRepository,
    private val auditLogManager: AuditLogManager,
    private val masterPasswordManager: MasterPasswordManager,
    private val encryptionManager: EncryptionManager,
    private val breachMonitor: BreachMonitor,
    private val backupManager: VaultBackupManager? = null,
    private val syncManager: DeviceSyncManager? = null,
    private val shareManager: CredentialShareManager? = null,
    private val emergencyManager: EmergencyAccessManager? = null,
    private val privacyModeManager: PrivacyModeManager?,
    private val deviceTrustManager: DeviceTrustManager?,
    private val authenticator: FirebaseAuthenticator
) : ViewModel() {

    private var userId: String = "guest"

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

    var trustedDevices = mutableStateListOf<DeviceTrustManager.DeviceInfo>()
    var isLoadingDevices by mutableStateOf(false)
        private set

    val keySecurityLevel: EncryptionManager.KeySecurityLevel
        get() = encryptionManager.getKeySecurityLevel()

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
                healthReport = PasswordHealthAnalyzer.analyze(allPasswords, breachMonitor)
                refreshSecurityInsights()
                
                // Defer security report as it's the heaviest and used in sub-screens
                updateSecurityReport()
            }
            
            // Load logs in background as they are for a separate screen
            launch {
                auditLogs.clear()
                auditLogs.addAll(auditLogManager.getLogs())
            }

            // Load trusted devices
            refreshDeviceList()
        }
    }

    /** Builds the security report if it is missing (used when opening the dashboard). */
    fun ensureSecurityReport() {
        if (securityReport != null) return
        viewModelScope.launch {
            try {
                updateSecurityReport()
            } catch (e: Exception) {
                securityReport = VaultSecurityReport(0, emptyList(), emptyList(), emptyList(), emptyList())
            }
        }
    }

    private suspend fun updateSecurityReport() {
        val vaultKey = masterPasswordManager.getVaultKey()
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
                healthReport = PasswordHealthAnalyzer.analyze(allPasswords, breachMonitor)
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
            "Stealth Protocol ACTIVE: Vault is now air-gapped and local-only."
        } else {
            "Stealth Protocol DISABLED: Cloud synchronization restored."
        }
        Toast.makeText(context, message, Toast.LENGTH_LONG).show()
    }

    fun syncVault(userId: String) {
        if (isOfflineMode || syncManager == null) return
        
        viewModelScope.launch {
            val vaultKey = masterPasswordManager.getVaultKey()
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
                val existing = repository.getPasswords().find { it.serviceName.equals(service, true) && it.username == username }
                val isUpdate = existing != null
                
                repository.savePassword(service, username, password, notes, id = existing?.id ?: 0)
                
                val logMsg = if (isUpdate) "Updated password for $service" else "Added new password for $service"
                auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, logMsg)

                allPasswords = repository.getPasswords()
                filterPasswords()

                launch(Dispatchers.Default) {
                    healthReport = PasswordHealthAnalyzer.analyze(allPasswords, breachMonitor)
                    refreshSecurityInsights()
                    updateSecurityReport()
                }

                withContext(Dispatchers.Main) {
                    onComplete()
                }
            } catch (e: IllegalStateException) {
                // Vault is locked — getVaultKey() returned null
                PrivacyLogger.e("PasswordViewModel", "Vault is locked, cannot save", e)
                withContext(Dispatchers.Main) {
                    onError("Session expired. Please lock and unlock the app again.")
                }
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Failed to add password", e)
                withContext(Dispatchers.Main) {
                    onError("Failed to save. Please try again.")
                }
            }
        }
    }

    fun deletePassword(item: PasswordItem) {
        viewModelScope.launch {
            repository.deletePassword(item.id)
            auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, "Deleted password for ${item.serviceName}")
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
            val vaultKey = masterPasswordManager.getVaultKey()
            val salt = masterPasswordManager.getSalt(context)?.let { android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP) }
            
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
            val vaultKey = masterPasswordManager.getVaultKey()
            if (vaultKey != null && backupManager != null) {
                try {
                    backupManager.importBackup(file, vaultKey, vaultKey)
                    auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, "Vault imported from ${file.name}")
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

    fun shareCredential(senderId: String, recipientId: String, credentialId: Int, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                if (recipientId.isBlank()) return@launch onResult(false, "Enter a recipient ID")
                val item = allPasswords.find { it.id == credentialId }
                    ?: return@launch onResult(false, "Credential not found")
                val manager = shareManager ?: return@launch onResult(false, "Sharing is unavailable")
                // PasswordItem's @Serializable uses constructor params (initialServiceName=""),
                // not the lazy-decrypt getters. Build a plain JSON with the actual decrypted values.
                val payloadMap = mapOf(
                    "id" to item.id,
                    "serviceName" to item.serviceName,
                    "username" to item.username,
                    "password" to item.password,
                    "notes" to (item.notes ?: ""),
                    "isFavorite" to item.isFavorite,
                    "createdAt" to item.createdAt
                )
                val payload = Json.encodeToString(kotlinx.serialization.json.JsonObject.serializer(),
                    kotlinx.serialization.json.buildJsonObject {
                        payloadMap.forEach { (k, v) ->
                            when (v) {
                                is Int -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                                is Long -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                                is Boolean -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                                is String -> put(k, kotlinx.serialization.json.JsonPrimitive(v))
                                else -> put(k, kotlinx.serialization.json.JsonPrimitive(v.toString()))
                            }
                        }
                    }
                )
                manager.shareCredential(senderId, recipientId, payload)
                auditLogManager.log(AuditLogManager.EventType.CREDENTIAL_SHARED, "Shared ${item.serviceName}")
                onResult(true, "Shared securely")
            } catch (e: Exception) {
                onResult(false, e.message ?: "Share failed")
            }
        }
    }

    fun changeMasterPassword(context: Context, newPassword: String, onComplete: (AuthResult) -> Unit) {
        viewModelScope.launch {
            try {
                // Zero-knowledge: master password is LOCAL only. Never sent to Firebase.
                // Firebase Auth password stays unchanged (it's the account password, not the vault key).
                masterPasswordManager.changeMasterPassword(context, newPassword.toCharArray())
                auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, "Master password changed")
                onComplete(AuthResult.Success(authenticator.currentUser!!))
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Password change failed", e)
                onComplete(AuthResult.Error(e.message ?: "Unknown error"))
            }
        }
    }

    fun rotateVaultKey(context: Context, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch {
            try {
                repository.rotateVaultKey(context)
                auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, "Vault Key rotated (Full re-encryption)")
                loadPasswords()
                onComplete(true)
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Vault key rotation failed", e)
                onComplete(false)
            }
        }
    }

    /**
     * Purges all decrypted data and cached items from the ViewModel.
     */
    fun lockVault() {
        allPasswords.forEach { it.clearDecryptedData() }
        allPasswords = emptyList()
        passwords.clear()
        auditLogs.clear()
        healthReport = PasswordHealthAnalyzer.HealthReport(100, emptyList(), emptyList(), emptyList(), emptyList())
        securityReport = null
        recommendations.clear()
        securityAlerts.clear()
    }

    fun setUserId(uid: String) {
        userId = uid
        refreshDeviceList()
    }

    fun refreshDeviceList() {
        val manager = deviceTrustManager ?: return
        viewModelScope.launch {
            isLoadingDevices = true
            try {
                val devices = manager.getTrustedDevices(userId)
                trustedDevices.clear()
                trustedDevices.addAll(devices)
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Failed to load device list", e)
            } finally {
                isLoadingDevices = false
            }
        }
    }

    fun revokeDevice(deviceId: String, onComplete: (Boolean) -> Unit) {
        val manager = deviceTrustManager ?: return
        viewModelScope.launch {
            try {
                manager.revokeDeviceTrust(userId, deviceId)
                refreshDeviceList()
                auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, "Revoked trust for ${com.hariharan.zerokey.core.common.PrivacyLogger.mask(deviceId)}")
                onComplete(true)
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Failed to revoke device", e)
                onComplete(false)
            }
        }
    }
}
