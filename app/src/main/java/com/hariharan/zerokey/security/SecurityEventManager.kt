package com.hariharan.zerokey.security

import com.hariharan.zerokey.core.database.AuditLogEntity
import com.hariharan.zerokey.security.AuditLogManager.EventType

/**
 * Detects suspicious activity patterns and anomalies within the vault.
 */
class SecurityEventManager(private val auditLogManager: AuditLogManager) {

    data class SecurityAlert(val title: String, val message: String, val timestamp: Long)

    /**
     * Checks for common attack patterns in the audit logs.
     */
    suspend fun detectAnomalies(): List<SecurityAlert> {
        val logs = auditLogManager.getAllLogs()
        val alerts = mutableListOf<SecurityAlert>()

        // 1. Detect multiple rapid password views (Credential Harvesting)
        if (detectRapidPasswordViews(logs)) {
            alerts.add(SecurityAlert("Credential Harvesting Detected", "Multiple passwords viewed in a very short time.", System.currentTimeMillis()))
        }

        // 2. Detect repeated unlock failures (Brute Force)
        if (detectBruteForceAttempts(logs)) {
            alerts.add(SecurityAlert("Potential Brute Force", "Multiple failed login attempts detected recently.", System.currentTimeMillis()))
        }

        // 3. Detect sensitive exports
        val recentExports = logs.filter { it.eventType == EventType.VAULT_EXPORTED.name && (System.currentTimeMillis() - it.timestamp < 3600000) }
        if (recentExports.isNotEmpty()) {
            alerts.add(SecurityAlert("Vault Exported", "A backup was created within the last hour.", System.currentTimeMillis()))
        }

        return alerts
    }

    private fun detectRapidPasswordViews(logs: List<AuditLogEntity>): Boolean {
        val views = logs.filter { it.eventType == EventType.PASSWORD_VIEWED.name }
            .sortedByDescending { it.timestamp }
        
        if (views.size < 5) return false
        
        // If 5 passwords viewed in under 60 seconds
        return (views[0].timestamp - views[4].timestamp) < 60000
    }

    private fun detectBruteForceAttempts(logs: List<AuditLogEntity>): Boolean {
        val failures = logs.filter { it.eventType == EventType.LOGIN_FAILURE.name }
            .sortedByDescending { it.timestamp }
            
        if (failures.size < 3) return false
        
        // If 3 failures in under 5 minutes
        return (System.currentTimeMillis() - failures[0].timestamp) < 300000
    }
}
