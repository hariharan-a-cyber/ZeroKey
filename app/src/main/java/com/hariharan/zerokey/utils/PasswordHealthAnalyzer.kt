package com.hariharan.zerokey.utils

import com.hariharan.zerokey.core.security.BreachMonitor
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository

data class HealthReport(
    val weakPasswords: List<PasswordItem>,
    val duplicatePasswords: List<PasswordItem>,
    val compromisedPasswords: List<PasswordItem>,
    val score: Int
)

class PasswordHealthAnalyzer(
    private val breachMonitor: BreachMonitor,
    private val repository: PasswordRepository? = null,
    // Re-check at most every 7 days per credential. Cached results younger than
    // this are trusted; older results are revalidated against HIBP.
    private val cacheTtlMs: Long = 7L * 24 * 60 * 60 * 1000
) {

    suspend fun analyze(passwords: List<PasswordItem>): HealthReport {
        val weak = passwords.filter {
            PasswordUtils.calculateStrength(it.password) == PasswordStrength.WEAK
        }

        val passwordCounts = passwords.groupBy { it.password }
        val duplicates = passwordCounts.filter { it.value.size > 1 }.values.flatten()

        // Breach check: re-use cached result when fresh; otherwise call HIBP
        // (k-anonymity protected) and persist the result for next time.
        val now = System.currentTimeMillis()
        val compromised = passwords.filter { item ->
            val cacheFresh = item.lastBreachCheck > 0 &&
                (now - item.lastBreachCheck) < cacheTtlMs
            if (cacheFresh) {
                item.breachFound
            } else {
                val found = breachMonitor.checkBreach(item.password.toCharArray())
                repository?.markBreachChecked(item.id, found)
                found
            }
        }

        val total = passwords.size.coerceAtLeast(1)
        val penalty = weak.size * 2 + duplicates.size * 1 + compromised.size * 5
        val rawScore = 100 - (penalty * 100 / total).coerceIn(0, 100)
        val score = rawScore.coerceIn(0, 100)

        return HealthReport(weak, duplicates, compromised, score)
    }
}
