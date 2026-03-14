package com.hariharan.zerokey.viewmodel

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.security.AuditLogManager

class PasswordViewModelFactory(
    private val repository: PasswordRepository,
    private val auditLogManager: AuditLogManager,
    private val backupManager: VaultBackupManager? = null
) : ViewModelProvider.Factory {
    override fun <T : ViewModel> create(modelClass: Class<T>): T {
        if (modelClass.isAssignableFrom(PasswordViewModel::class.java)) {
            @Suppress("UNCHECKED_CAST")
            return PasswordViewModel(repository, auditLogManager, backupManager) as T
        }
        throw IllegalArgumentException("Unknown ViewModel class")
    }
}
