package com.hariharan.zerokey.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.security.AuditLogManager
import com.hariharan.zerokey.security.DeviceTrustManager
import com.hariharan.zerokey.sync.DeviceSyncManager
import com.hariharan.zerokey.sharing.CredentialShareManager
import com.hariharan.zerokey.emergency.EmergencyAccessManager

class PasswordViewModelFactory(
    private val repository: PasswordRepository,
    private val auditLogManager: AuditLogManager,
    private val backupManager: VaultBackupManager? = null,
    private val syncManager: DeviceSyncManager? = null,
    private val shareManager: CredentialShareManager? = null,
    private val emergencyManager: EmergencyAccessManager? = null,
    private val deviceTrustManager: DeviceTrustManager? = null
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(PasswordViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return PasswordViewModel(
                repository = repository,
                auditLogManager = auditLogManager,
                backupManager = backupManager,
                syncManager = syncManager,
                shareManager = shareManager,
                emergencyManager = emergencyManager,
                deviceTrustManager = deviceTrustManager
            ) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}
