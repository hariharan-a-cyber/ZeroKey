package com.hariharan.zerokey.securityanalytics

import kotlin.math.roundToInt

class SecurityScoreCalculator(
    private val entropyAnalyzer: PasswordEntropyAnalyzer
) {
    fun calculate(report: VaultSecurityReport): Int {
        var score = 100

        val totalCredentials = report.totalCredentials.coerceAtLeast(1)

        // Weak password penalty: -2 per weak credential, max -40
        val weakPenalty = ((report.weakPasswords.size.toFloat() / totalCredentials) * 40).roundToInt()
        score -= weakPenalty.coerceAtMost(40)

        // Duplicate penalty: -1.5 per duplicate group member, max -30
        val dupCount = report.duplicateGroups.sumOf { it.credentialIds.size - 1 }
        val dupPenalty = ((dupCount.toFloat() / totalCredentials) * 30).roundToInt()
        score -= dupPenalty.coerceAtMost(30)

        // Breach penalty: -10 per breached credential, max -40
        val breachPenalty = (report.breachedCredentials.size * 10).coerceAtMost(40)
        score -= breachPenalty

        // Low entropy penalty: -0.5 per low-entropy password, max -20
        val lowEntropyCount = report.entropyResults.count { it.entropyBits < 40f }
        val entropyPenalty = ((lowEntropyCount.toFloat() / totalCredentials) * 20).roundToInt()
        score -= entropyPenalty.coerceAtMost(20)

        return score.coerceIn(0, 100)
    }

    fun scoreGrade(score: Int): SecurityGrade = when {
        score >= 90 -> SecurityGrade.EXCELLENT
        score >= 75 -> SecurityGrade.GOOD
        score >= 50 -> SecurityGrade.FAIR
        score >= 25 -> SecurityGrade.POOR
        else        -> SecurityGrade.CRITICAL
    }
}
