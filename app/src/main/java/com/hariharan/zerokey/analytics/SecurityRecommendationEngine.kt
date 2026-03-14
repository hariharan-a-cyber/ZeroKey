package com.hariharan.zerokey.analytics

import com.hariharan.zerokey.utils.PasswordHealthAnalyzer

/**
 * Generates actionable security recommendations based on vault analysis.
 */
object SecurityRecommendationEngine {

    sealed class Recommendation(val title: String, val description: String, val priority: Priority) {
        object ReusedPasswords : Recommendation("Change Reused Passwords", "Multiple accounts use the same password. If one is leaked, all are at risk.", Priority.HIGH)
        object WeakPasswords : Recommendation("Strengthen Weak Passwords", "Some passwords are easy to guess. Use the generator for stronger alternatives.", Priority.MEDIUM)
        object CompromisedPasswords : Recommendation("Immediate Action Required", "Some credentials match known data breaches. Change them immediately.", Priority.CRITICAL)
        object OldPasswords : Recommendation("Rotate Old Credentials", "You haven't updated some passwords in over 6 months.", Priority.LOW)
    }

    enum class Priority { LOW, MEDIUM, HIGH, CRITICAL }

    fun getRecommendations(report: PasswordHealthAnalyzer.HealthReport): List<Recommendation> {
        val list = mutableListOf<Recommendation>()
        if (report.compromisedPasswords.isNotEmpty()) list.add(Recommendation.CompromisedPasswords)
        if (report.duplicatePasswords.isNotEmpty()) list.add(Recommendation.ReusedPasswords)
        if (report.weakPasswords.isNotEmpty()) list.add(Recommendation.WeakPasswords)
        // Add more logic for outdated passwords if timestamp tracking is implemented
        return list
    }
}
