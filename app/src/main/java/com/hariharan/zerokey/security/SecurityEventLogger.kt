package com.hariharan.zerokey.security

import com.hariharan.zerokey.data.database.AuditLogDao
import com.hariharan.zerokey.data.database.AuditLogEntity

sealed class SecurityEvent {
    data class AutofillBlocked(
        val requestedDomain: String?,
        val packageName: String,
        val reason: String
    ) : SecurityEvent()

    data class SuspiciousDomainAccess(val domain: String) : SecurityEvent()
    data class HmacVerificationFailed(val context: String) : SecurityEvent()
}

/**
 * Requirement 8: Security Activity Monitoring.
 * Logs high-level security events to the audit database.
 */
class SecurityEventLogger(private val auditLogDao: AuditLogDao) {

    suspend fun log(event: SecurityEvent) {
        val details = when (event) {
            is SecurityEvent.AutofillBlocked -> 
                "Autofill blocked for domain ${event.requestedDomain ?: "unknown"} in package ${event.packageName}. Reason: ${event.reason}"
            is SecurityEvent.SuspiciousDomainAccess -> 
                "Suspicious domain access attempt: ${event.domain}"
            is SecurityEvent.HmacVerificationFailed -> 
                "HMAC verification failed in context: ${event.context}"
        }
        
        auditLogDao.insertLog(AuditLogEntity(
            eventType = "SECURITY_ALERT",
            details = details,
            timestamp = System.currentTimeMillis()
        ))
    }
}
