package com.hariharan.zerokey.utils

import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.core.security.BreachMonitor

/**
 * Analyzes the user's vault for security weaknesses.
 */
object PasswordHealthAnalyzer {

    data class HealthReport(
        val score: Int, // 0-100
        val weakPasswords: List<PasswordItem>,
        val duplicatePasswords: List<PasswordItem>,
        val oldPasswords: List<PasswordItem>,
        val compromisedPasswords: List<PasswordItem>
    )

    suspend fun analyze(passwords: List<PasswordItem>, breachMonitor: BreachMonitor): HealthReport {
        if (passwords.isEmpty()) {
            return HealthReport(100, emptyList(), emptyList(), emptyList(), emptyList())
        }

        val weak = passwords.filter { PasswordUtils.calculateStrength(it.password) in listOf(PasswordStrength.WEAK, PasswordStrength.MEDIUM) }
        
        val duplicates = passwords.groupBy { it.password }
            .filter { it.value.size > 1 }
            .flatMap { it.value }

        // Consider passwords older than 6 months as 'old'
        val sixMonthsAgo = System.currentTimeMillis() - 15552000000L
        val old = passwords.filter { item ->
            item.createdAt < sixMonthsAgo
        }
        
        // Query breachMonitor for each password
        val compromised = passwords.filter { item ->
            breachMonitor.checkBreach(item.password.toCharArray())
        }

        // Calculate score
        val total = passwords.size
        val penalty = (weak.size * 5) + (duplicates.size * 10) + (compromised.size * 25) + (old.size * 2)
        val score = (100 - (penalty / total.coerceAtLeast(1))).coerceIn(0, 100)

        return HealthReport(
            score = score,
            weakPasswords = weak,
            duplicatePasswords = duplicates,
            oldPasswords = old,
            compromisedPasswords = compromised
        )
    }
}
