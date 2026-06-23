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

import com.hariharan.zerokey.utils.HealthReport
import com.hariharan.zerokey.utils.PasswordHealthAnalyzer
import com.hariharan.zerokey.utils.PasswordStrength
import com.hariharan.zerokey.utils.PasswordUtils
import kotlinx.coroutines.tasks.await
import kotlinx.coroutines.Dispatchers

import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.json.Json
import java.io.File
import javax.crypto.spec.SecretKeySpec
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import com.hariharan.zerokey.core.crypto.KeySecurityLevel
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
    private val hmacEngine: com.hariharan.zerokey.core.crypto.HmacEngine,
    private val breachMonitor: BreachMonitor,
    private val backupManager: VaultBackupManager? = null,
    private val syncManager: DeviceSyncManager? = null,
    private val shareManager: CredentialShareManager? = null,
    private val featureAccessManager: com.hariharan.zerokey.security.FeatureAccessManager? = null,
    private val privacyModeManager: PrivacyModeManager?,
    private val deviceTrustManager: DeviceTrustManager?,
    private val authenticator: FirebaseAuthenticator,
    private val emergencyAccessManager: com.hariharan.zerokey.emergency.EmergencyAccessManager? = null
) : ViewModel() {

    var currentUserId: String by mutableStateOf("guest")
        private set

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

    var healthReport by mutableStateOf(HealthReport(emptyList(), emptyList(), emptyList(), 100))
        private set

    var securityReport by mutableStateOf<VaultSecurityReport?>(null)
        private set

    var recommendations = mutableStateListOf<SecurityRecommendationEngine.Recommendation>()
        private set

    var securityAlerts = mutableStateListOf<SecurityEventManager.SecurityAlert>()
        private set

    var isOfflineMode by mutableStateOf(privacyModeManager?.isOfflineOnly() ?: false)
        private set

    var emergencyConfig by mutableStateOf<com.hariharan.zerokey.emergency.EmergencyAccessConfig?>(null)
        private set

    var trustedDevices = mutableStateListOf<com.hariharan.zerokey.security.DeviceInfo>()
    var isLoadingDevices by mutableStateOf(false)
        private set

    var isConfiguringEmergency by mutableStateOf(false)
        private set

    var incomingShares = mutableStateListOf<com.hariharan.zerokey.sharing.IncomingShare>()
        private set

    var activeEmergencyRequests = mutableStateListOf<com.hariharan.zerokey.emergency.EmergencyAccessRequest>()
        private set

    var pendingEmergencyRequestsForMe = mutableStateListOf<com.hariharan.zerokey.emergency.EmergencyAccessRequest>()
        private set

    var vaultsIAmContactFor = mutableStateListOf<com.hariharan.zerokey.emergency.EmergencyAccessConfig>()
        private set

    val keySecurityLevel: KeySecurityLevel
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
                val analyzer = PasswordHealthAnalyzer(breachMonitor, repository)
                healthReport = analyzer.analyze(allPasswords)
                refreshSecurityInsights()
                
                // Defer security report as it's the heaviest and used in sub-screens
                updateSecurityReport()
            }
            
            // Load logs in background as they are for a separate screen
            launch {
                auditLogs.clear()
                auditLogs.addAll(auditLogManager.getAllLogs())
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
                val analyzer = PasswordHealthAnalyzer(breachMonitor, repository)
                healthReport = analyzer.analyze(allPasswords)
                refreshSecurityInsights()
                updateSecurityReport()
            }
        }
    }

    private fun loadAuditLogs() {
        viewModelScope.launch {
            auditLogs.clear()
            auditLogs.addAll(auditLogManager.getAllLogs())
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

    // syncVault() removed — SyncViewModel.performSync() is the only sync entry point.
    // The old version reused the vault key for both encryption and HMAC (broken key separation).

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
                    val analyzer = PasswordHealthAnalyzer(breachMonitor, repository)
                    healthReport = analyzer.analyze(allPasswords)
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
            val salt = masterPasswordManager.getSalt(context)?.let {
                android.util.Base64.encodeToString(it, android.util.Base64.NO_WRAP)
            }

            if (vaultKey == null || salt == null || backupManager == null) {
                onComplete(false)
                return@launch
            }

            // SECURITY: derive distinct subkeys for encryption and MAC. Never
            // reuse the raw vault key for both.
            val encKeyBytes = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-backup-enc-v1")
            val macKeyBytes = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-backup-mac-v1")
            val encKey = javax.crypto.spec.SecretKeySpec(encKeyBytes, "AES")
            val macKey = javax.crypto.spec.SecretKeySpec(macKeyBytes, "HmacSHA256")

            try {
                backupManager.exportBackup(file, encKey, macKey, salt)
                auditLogManager.log(AuditLogManager.EventType.VAULT_EXPORTED, "Vault exported")
                onComplete(true)
            } catch (e: Exception) {
                com.hariharan.zerokey.core.common.PrivacyLogger.e(
                    "PasswordViewModel",
                    "Export failed: ${e.message}"
                )
                onComplete(false)
            } finally {
                encKeyBytes.fill(0)
                macKeyBytes.fill(0)
            }
        }
    }

    fun importVault(file: File, onComplete: (Boolean) -> Unit) {
        viewModelScope.launch {
            val vaultKey = masterPasswordManager.getVaultKey()
            if (vaultKey == null || backupManager == null) {
                onComplete(false)
                return@launch
            }

            val encKeyBytes = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-backup-enc-v1")
            val macKeyBytes = hmacEngine.deriveSubKey(vaultKey.encoded, "zk-backup-mac-v1")
            val encKey = javax.crypto.spec.SecretKeySpec(encKeyBytes, "AES")
            val macKey = javax.crypto.spec.SecretKeySpec(macKeyBytes, "HmacSHA256")

            try {
                backupManager.importBackup(file, encKey, macKey)
                auditLogManager.log(AuditLogManager.EventType.SETTINGS_CHANGED, "Vault imported")
                loadPasswords()
                loadAuditLogs()
                onComplete(true)
            } catch (e: Exception) {
                com.hariharan.zerokey.core.common.PrivacyLogger.e(
                    "PasswordViewModel",
                    "Import failed: ${e.message}"
                )
                onComplete(false)
            } finally {
                encKeyBytes.fill(0)
                macKeyBytes.fill(0)
            }
        }
    }

    fun shareCredential(senderId: String, recipientId: String, credentialId: Int, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                if (featureAccessManager?.hasAccess(
                        com.hariharan.zerokey.security.FeatureAccessManager.Feature.SECURE_SHARING
                    ) == false
                ) {
                    onResult(false, "Secure Sharing requires an active subscription.")
                    return@launch
                }
                val shareMgr = shareManager ?: return@launch onResult(false, "Sharing unavailable")
                val item = passwords.find { it.id == credentialId }
                    ?: return@launch onResult(false, "Credential not found")

                val payload = buildJsonObject {
                    put("serviceName", item.serviceName)
                    put("username", item.username)
                    put("password", item.password)
                    item.notes?.let { put("notes", it) }
                    put("sharedAt", System.currentTimeMillis())
                }.toString()

                shareMgr.shareCredential(senderId, recipientId, payload)
                onResult(true, "Credential shared securely.")
            } catch (e: Exception) {
                onResult(false, e.message ?: "Share failed")
            }
        }
    }

    suspend fun fetchRecipientFingerprint(recipientId: String): String? {
        return shareManager?.fetchRecipientFingerprint(recipientId)
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
        healthReport = HealthReport(emptyList(), emptyList(), emptyList(), 100)
        securityReport = null
        recommendations.clear()
        securityAlerts.clear()
    }

    fun setUserId(uid: String) {
        currentUserId = uid
        masterPasswordManager.setUserId(uid)
        loadInitialData()
        refreshEmergencyConfig()
        refreshOwnerActivity()
        refreshIncomingShares()
        refreshEmergencyRequests()
    }

    fun refreshEmergencyRequests() {
        if (currentUserId == "guest") return
        viewModelScope.launch {
            try {
                // 1. Requests I've made
                val myRequests = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                    .collection("emergency_access_requests")
                    .whereEqualTo("requesterUid", currentUserId)
                    .get().await()
                    .toObjects(com.hariharan.zerokey.emergency.EmergencyAccessRequest::class.java)
                
                PrivacyLogger.d("PasswordViewModel", "Found ${myRequests.size} requests made by me")
                activeEmergencyRequests.clear()
                activeEmergencyRequests.addAll(myRequests)

                // 2. Requests for my vault
                val forMe = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                    .collection("emergency_access_requests")
                    .whereEqualTo("ownerUid", currentUserId)
                    .whereEqualTo("status", com.hariharan.zerokey.emergency.EmergencyStatus.PENDING.name)
                    .get().await()
                    .toObjects(com.hariharan.zerokey.emergency.EmergencyAccessRequest::class.java)
                
                PrivacyLogger.d("PasswordViewModel", "Found ${forMe.size} pending requests for my vault")
                pendingEmergencyRequestsForMe.clear()
                pendingEmergencyRequestsForMe.addAll(forMe)

                // 3. Vaults that have nominated me
                val nominatedBy = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                    .collection("emergency_access_config")
                    .whereEqualTo("trustedContactUid", currentUserId)
                    .get().await()
                    .toObjects(com.hariharan.zerokey.emergency.EmergencyAccessConfig::class.java)
                
                PrivacyLogger.d("PasswordViewModel", "Found ${nominatedBy.size} vaults that nominated me")
                vaultsIAmContactFor.clear()
                vaultsIAmContactFor.addAll(nominatedBy)
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Failed to refresh emergency requests", e)
            }
        }
    }

    fun requestEmergencyAccess(context: Context, ownerUid: String, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                val manager = emergencyAccessManager ?: throw IllegalStateException("Emergency Access unavailable")
                val requestId = java.util.UUID.randomUUID().toString()
                
                // Sign the request: requestId + ownerUid + requesterUid
                val dataToSign = requestId + ownerUid + currentUserId
                masterPasswordManager.ensureIdentityKeys(context, currentUserId)
                val signature = masterPasswordManager.signData(currentUserId, dataToSign)

                val request = com.hariharan.zerokey.emergency.EmergencyAccessRequest(
                    requestId = requestId,
                    ownerUid = ownerUid,
                    requesterUid = currentUserId,
                    requesterSignature = signature
                )

                val result = manager.requestAccess(request)
                when (result) {
                    is com.hariharan.zerokey.emergency.AccessRequestResult.RequestAccepted -> {
                        refreshEmergencyRequests()
                        onResult(true, "Request submitted. Access will be available in 48 hours if not cancelled.")
                    }
                    is com.hariharan.zerokey.emergency.AccessRequestResult.OwnerStillActive -> {
                        onResult(false, "Owner is still active. Please wait ${result.daysUntilEligible} more days.")
                    }
                    is com.hariharan.zerokey.emergency.AccessRequestResult.NotConfigured -> {
                        onResult(false, "Owner has not configured you as an emergency contact.")
                    }
                    is com.hariharan.zerokey.emergency.AccessRequestResult.Unauthorized -> {
                        onResult(false, "You are not authorized for this vault.")
                    }
                    is com.hariharan.zerokey.emergency.AccessRequestResult.Failure -> {
                        onResult(false, result.reason)
                    }
                    else -> onResult(false, "Request failed.")
                }
            } catch (e: Exception) {
                onResult(false, e.message ?: "Request failed")
            }
        }
    }

    fun claimEmergencyAccess(context: Context, requestId: String, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                val manager = emergencyAccessManager ?: throw IllegalStateException("Emergency Access unavailable")
                val result = manager.claimVaultKey(requestId)
                
                if (result is com.hariharan.zerokey.emergency.ClaimResult.Success) {
                    val shareMgr = shareManager ?: throw IllegalStateException("Sharing logic unavailable")
                    val request = activeEmergencyRequests.find { it.requestId == requestId }!!
                    
                    val mockShare = com.hariharan.zerokey.sharing.IncomingShare(
                        id = requestId,
                        senderUserId = request.ownerUid,
                        encryptedPayload = result.encryptedVaultKey,
                        timestamp = System.currentTimeMillis()
                    )
                    
                    val rawVaultKeyB64 = shareMgr.decryptShare(context, mockShare, currentUserId)
                    val rawVaultKey = android.util.Base64.decode(rawVaultKeyB64, android.util.Base64.NO_WRAP)
                    
                    masterPasswordManager.restoreVaultKey(rawVaultKey, request.ownerUid)
                    onResult(true, "Vault unlocked successfully.")
                } else if (result is com.hariharan.zerokey.emergency.ClaimResult.DelayNotElapsed) {
                    onResult(false, "Security delay not elapsed. ${result.hoursRemaining} hours remaining.")
                } else {
                    onResult(false, "Claim failed.")
                }
            } catch (e: Exception) {
                onResult(false, e.message ?: "Claim failed")
            }
        }
    }

    fun cancelEmergencyRequest(requestId: String, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                val manager = emergencyAccessManager ?: throw IllegalStateException("Emergency Access unavailable")
                val signature = masterPasswordManager.signData(currentUserId, requestId + "CANCEL")
                val result = manager.cancelRequest(currentUserId, requestId, signature)
                if (result is com.hariharan.zerokey.emergency.CancelResult.Cancelled) {
                    refreshEmergencyRequests()
                    onResult(true, "Request cancelled.")
                } else {
                    onResult(false, "Cancellation failed.")
                }
            } catch (e: Exception) {
                onResult(false, e.message ?: "Cancel failed")
            }
        }
    }

    fun approveEmergencyRequestEarly(requestId: String, onResult: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                val manager = emergencyAccessManager ?: throw IllegalStateException("Emergency Access unavailable")
                val signature = masterPasswordManager.signData(currentUserId, requestId + "APPROVE")
                val result = manager.manualApprove(currentUserId, requestId, signature)
                if (result is com.hariharan.zerokey.emergency.EmergencySetupResult.Success) {
                    refreshEmergencyRequests()
                    onResult(true, "Access granted early.")
                } else {
                    onResult(false, "Approval failed.")
                }
            } catch (e: Exception) {
                onResult(false, e.message ?: "Approval failed")
            }
        }
    }

    fun refreshIncomingShares() {
        if (currentUserId == "guest") return
        viewModelScope.launch {
            val shares = shareManager?.fetchIncomingShares(currentUserId) ?: emptyList()
            incomingShares.clear()
            incomingShares.addAll(shares)
        }
    }

    fun acceptShare(context: Context, share: com.hariharan.zerokey.sharing.IncomingShare, onComplete: (Boolean, String) -> Unit) {
        viewModelScope.launch {
            try {
                val mgr = shareManager ?: throw IllegalStateException("Sharing unavailable")
                val plaintext = mgr.decryptShare(context, share, currentUserId)
                
                val json = Json { ignoreUnknownKeys = true }
                val jsonObj = json.parseToJsonElement(plaintext).jsonObject
                
                val service = jsonObj["serviceName"]?.jsonPrimitive?.content ?: throw IllegalStateException("Missing service name")
                val user = jsonObj["username"]?.jsonPrimitive?.content ?: throw IllegalStateException("Missing username")
                val pass = jsonObj["password"]?.jsonPrimitive?.content ?: throw IllegalStateException("Missing password")
                val originalNotes = jsonObj["notes"]?.jsonPrimitive?.content ?: ""
                
                // Add sharing attribution
                val attribution = "\n\n[Shared from: ${share.senderUserId}]"
                val finalNotes = if (originalNotes.isBlank()) attribution.trim() else "$originalNotes$attribution"
                
                repository.savePassword(service, user, pass, finalNotes)
                mgr.deleteShare(share.id)
                
                loadPasswords()
                refreshIncomingShares()
                onComplete(true, "Shared password accepted and saved.")
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Accept share failed", e)
                onComplete(false, "Error: The shared data was malformed or incompatible.")
            }
        }
    }

    fun deleteIncomingShare(shareId: String) {
        viewModelScope.launch {
            try {
                shareManager?.deleteShare(shareId)
                refreshIncomingShares()
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Delete share failed", e)
            }
        }
    }

    fun refreshEmergencyConfig() {
        viewModelScope.launch {
            try {
                val doc = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                    .collection("emergency_access_config")
                    .document(currentUserId)
                    .get()
                    .await()
                emergencyConfig = doc.toObject(com.hariharan.zerokey.emergency.EmergencyAccessConfig::class.java)
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Failed to fetch emergency config", e)
            }
        }
    }

    /**
     * Refresh `lastOwnerActivity` on the owner's emergency_access_config doc.
     * Called every time the owner successfully unlocks / re-enters the app, so
     * the "inactivity" trigger reflects actual activity instead of just
     * time-since-setup. Best-effort: failures (offline, no config) are silent.
     */
    private fun refreshOwnerActivity() {
        if (currentUserId.isBlank() || currentUserId == "guest") return
        viewModelScope.launch {
            try {
                com.google.firebase.firestore.FirebaseFirestore.getInstance()
                    .collection("emergency_access_config")
                    .document(currentUserId)
                    .update("lastOwnerActivity", System.currentTimeMillis())
                    .await()
            } catch (_: Exception) {
                // Document may not exist (user hasn't configured Emergency Access)
                // or device is offline — both fine, just skip the refresh.
            }
        }
    }

    fun setupEmergencyAccess(
        context: Context,
        contactUid: String,
        contactEmail: String,
        inactivityDays: Int,
        onResult: (Boolean, String) -> Unit
    ) {
        viewModelScope.launch {
            isConfiguringEmergency = true
            try {
                val manager = emergencyAccessManager ?: throw IllegalStateException("Emergency Access unavailable")
                val vaultKey = masterPasswordManager.getVaultKey() ?: throw IllegalStateException("Vault is locked")
                
                // 1. Ensure owner has identity keys for signing
                masterPasswordManager.ensureIdentityKeys(context, currentUserId)
                val ownerPubKey = masterPasswordManager.getIdentityPublicKey(context, currentUserId)!!

                // 2. Fetch contact's keys
                val contactPubKeyB64 = shareManager?.fetchPublicKey(contactUid) 
                    ?: throw IllegalArgumentException("Contact not found. They must be a ZeroKey user.")
                
                val contactIdentityKeyB64 = shareManager.fetchIdentityKey(contactUid)
                    ?: throw IllegalArgumentException("Contact has not updated to the latest version of ZeroKey.")
                
                // 3. Encrypt Vault Key for contact
                val contactHandle = com.google.crypto.tink.KeysetHandle.readNoSecret(
                    com.google.crypto.tink.BinaryKeysetReader.withBytes(android.util.Base64.decode(contactPubKeyB64, android.util.Base64.NO_WRAP))
                )
                val hybridEncrypt = contactHandle.getPrimitive(com.google.crypto.tink.HybridEncrypt::class.java)
                val encryptedVK = hybridEncrypt.encrypt(vaultKey.encoded, "emergency:$currentUserId:$contactUid".toByteArray())
                val encryptedVK_B64 = android.util.Base64.encodeToString(encryptedVK, android.util.Base64.NO_WRAP)

                // 4. Sign the config
                val dataToSign = currentUserId + contactUid + encryptedVK_B64
                val signature = masterPasswordManager.signData(currentUserId, dataToSign)

                val config = com.hariharan.zerokey.emergency.EmergencyAccessConfig(
                    ownerUid = currentUserId,
                    trustedContactUid = contactUid,
                    contactEmail = contactEmail,
                    inactivityDays = inactivityDays,
                    encryptedVaultKey = encryptedVK_B64,
                    iv = "", // Tink handles IV
                    ownerPublicKey = ownerPubKey,
                    contactPublicKey = contactPubKeyB64,
                    contactIdentityKey = contactIdentityKeyB64,
                    lastOwnerActivity = System.currentTimeMillis(),
                    setupSignature = signature,
                    status = com.hariharan.zerokey.emergency.EmergencyStatus.CONFIGURED
                )

                val result = manager.setupEmergencyAccess(config)
                if (result is com.hariharan.zerokey.emergency.EmergencySetupResult.Success) {
                    // Update state immediately from the object we just saved
                    emergencyConfig = config

                    refreshOwnerActivity() // Ensure Device B can discover us immediately
                    onResult(true, "Emergency Access enabled.")
                } else {
                    onResult(false, (result as com.hariharan.zerokey.emergency.EmergencySetupResult.Failure).reason)
                }
            } catch (e: Exception) {
                onResult(false, e.message ?: "Configuration failed")
            } finally {
                isConfiguringEmergency = false
            }
        }
    }

    fun refreshDeviceList() {
        val manager = deviceTrustManager ?: return
        viewModelScope.launch {
            isLoadingDevices = true
            try {
                val devices = manager.getTrustedDevices(currentUserId)
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
                manager.revokeDevice(currentUserId, deviceId)
                refreshDeviceList()
                auditLogManager.log(AuditLogManager.EventType.DEVICE_REVOKED, "Revoked trust for ${com.hariharan.zerokey.core.common.PrivacyLogger.mask(deviceId)}")
                onComplete(true)
            } catch (e: Exception) {
                PrivacyLogger.e("PasswordViewModel", "Failed to revoke device", e)
                onComplete(false)
            }
        }
    }

    fun getOwnSharingFingerprint(context: Context): String {
        return shareManager?.getOwnFingerprint(context) ?: "Unavailable"
    }

    fun decryptLogDetails(stored: String): String = auditLogManager.decryptDetails(stored)
}
