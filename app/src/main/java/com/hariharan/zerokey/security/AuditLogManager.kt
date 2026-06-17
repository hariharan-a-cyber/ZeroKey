package com.hariharan.zerokey.security

import com.hariharan.zerokey.core.database.AuditLogDao
import com.hariharan.zerokey.core.database.AuditLogEntity

/**
 * Manages the recording of security-critical audit logs.
 */
class AuditLogManager(private val auditLogDao: AuditLogDao) {

    enum class EventType(val description: String) {
        VAULT_UNLOCKED("Vault Unlocked"),
        PASSWORD_VIEWED("Password Viewed"),
        CREDENTIAL_SHARED("Credential Shared"),
        PASSWORD_COPIED("Password Copied"),
        VAULT_EXPORTED("Vault Exported"),
        AUTOFILL_USED("Autofill Used"),
        LOGIN_FAILURE("Failed Login Attempt"),
        SYNC_STARTED("Cloud Sync Started"),
        SYNC_COMPLETED("Cloud Sync Completed"),
        SETTINGS_CHANGED("Settings Changed")
    }

    suspend fun log(eventType: EventType, details: String) {
        auditLogDao.insertLog(AuditLogEntity(eventType = eventType.description, details = details))
    }

    suspend fun getLogs(): List<AuditLogEntity> {
        return auditLogDao.getAllLogs()
    }

    suspend fun clearLogs() {
        auditLogDao.clearLogs()
    }
}
