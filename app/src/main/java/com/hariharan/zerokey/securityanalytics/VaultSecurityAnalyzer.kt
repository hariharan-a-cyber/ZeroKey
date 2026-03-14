package com.hariharan.zerokey.securityanalytics

import com.hariharan.zerokey.data.model.PasswordItem
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import android.util.Base64

class VaultSecurityAnalyzer(
    private val entropyAnalyzer: PasswordEntropyAnalyzer,
    private val scoreCalculator: SecurityScoreCalculator
) {
    /**
     * Analyzes all credentials and produces a full report.
     * Password hashing for deduplication uses HMAC-SHA256 to avoid
     * storing or comparing plaintext passwords.
     */
    fun buildReport(
        credentials: List<PasswordItem>,
        hmacKey: ByteArray,
        breachedIds: Set<Int> = emptySet()
    ): VaultSecurityReport {
        val weak = mutableListOf<WeakPasswordItem>()
        val entropyResults = mutableListOf<EntropyResult>()
        val passwordBuckets = mutableMapOf<String, MutableList<PasswordItem>>()

        credentials.forEach { cred ->
            val entropy = entropyAnalyzer.analyze(cred.password)
            entropyResults.add(entropy)

            // Flag as weak
            if (entropy.strength == PasswordStrength.VERY_WEAK || entropy.strength == PasswordStrength.WEAK) {
                weak.add(WeakPasswordItem(cred.id, cred.serviceName, entropy.warnings.joinToString("; ")))
            }

            // Group duplicates using HMAC fingerprint (never compare raw passwords)
            val fingerprint = hmacFingerprint(cred.password, hmacKey)
            passwordBuckets.getOrPut(fingerprint) { mutableListOf() }.add(cred)
        }

        val duplicates = passwordBuckets.values
            .filter { it.size > 1 }
            .map { group ->
                DuplicateGroup(
                    passwordHash = hmacFingerprint(group.first().password, hmacKey),
                    credentialIds = group.map { it.id },
                    domains = group.map { it.serviceName }
                )
            }

        val breached = credentials
            .filter { breachedIds.contains(it.id) }
            .map { BreachedItem(it.id, it.serviceName, "HaveIBeenPwned", null) }

        val report = VaultSecurityReport(
            totalCredentials = credentials.size,
            weakPasswords = weak,
            duplicateGroups = duplicates,
            breachedCredentials = breached,
            entropyResults = entropyResults
        )

        report.securityScore = scoreCalculator.calculate(report)
        return report
    }

    private fun hmacFingerprint(password: String, key: ByteArray): String {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        val result = mac.doFinal(password.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(result, Base64.NO_WRAP)
    }
}
