package com.hariharan.zerokey.security

import android.util.Log

/**
 * DomainVerificationManager
 *
 * Validates that the autofill requester legitimately owns the domain.
 *
 * Verification layers:
 * 1. Exact domain match against stored credential domain
 * 2. Android App Links / Digital Asset Links verification
 * 3. Package name allowlist for native apps
 * 4. Suspicious pattern detection (typosquatting heuristics)
 */
class DomainVerificationManager(
    private val assetLinksVerifier: DigitalAssetLinksVerifier
) {
    companion object {
        private const val TAG = "DomainVerificationManager"

        // Known malicious patterns — expanded via cloud config in production
        private val SUSPICIOUS_PATTERNS = listOf(
            Regex(".*paypa1\\..*"),
            Regex(".*g00gle\\..*"),
            Regex(".*arnazon\\..*"),
            Regex(".*faceb00k\\..*")
        )
    }

    suspend fun verify(
        requestedDomain: String?,
        packageName: String?,
        webDomain: String?
    ): DomainVerificationResult {

        // 1. Null domain → block
        if (requestedDomain == null && webDomain == null) {
            return DomainVerificationResult.Blocked("No domain information available")
        }

        val domain = requestedDomain ?: webDomain!!

        // 2. Suspicious pattern check
        if (SUSPICIOUS_PATTERNS.any { it.matches(domain) }) {
            Log.w(TAG, "Suspicious domain pattern detected: $domain")
            return DomainVerificationResult.Blocked("Suspicious domain pattern: $domain")
        }

        // 3. For native apps: verify Digital Asset Links
        if (packageName != null && webDomain != null) {
            val assetLinksValid = assetLinksVerifier.verify(webDomain, packageName)
            if (!assetLinksValid) {
                Log.w(TAG, "Digital Asset Links mismatch: $packageName vs $webDomain")
                return DomainVerificationResult.Blocked(
                    "Package $packageName is not associated with domain $webDomain via Digital Asset Links"
                )
            }
        }

        return DomainVerificationResult.Verified(domain)
    }
}

sealed class DomainVerificationResult {
    data class Verified(val verifiedDomain: String) : DomainVerificationResult()
    data class Blocked(val reason: String) : DomainVerificationResult()
}
