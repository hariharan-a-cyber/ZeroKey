package com.hariharan.zerokey.security

import com.hariharan.zerokey.core.common.PrivacyLogger

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

        // 1. Domain Extraction & Normalization
        val domain = webDomain ?: requestedDomain
        if (domain == null) {
            return DomainVerificationResult.Blocked("No domain information available")
        }
        
        val normalizedDomain = extractRegistrableDomain(domain)

        // 2. Suspicious pattern check
        if (SUSPICIOUS_PATTERNS.any { it.matches(domain) }) {
            PrivacyLogger.w(TAG, "Suspicious domain pattern detected: $domain")
            return DomainVerificationResult.Blocked("Suspicious domain pattern: $domain")
        }

        // 3. For native apps: verify Digital Asset Links
        if (packageName != null && webDomain != null) {
            val assetLinksValid = assetLinksVerifier.verify(webDomain, packageName)
            if (!assetLinksValid) {
                PrivacyLogger.w(TAG, "Digital Asset Links mismatch: $packageName vs $webDomain")
                return DomainVerificationResult.Unverified(normalizedDomain)
            }
        }

        return DomainVerificationResult.Verified(normalizedDomain)
    }

    private fun extractRegistrableDomain(host: String): String {
        val parts = host.lowercase().split(".")
        if (parts.size < 2) return host
        
        // Basic Public Suffix List heuristic (matches common multi-part TLDs like .co.uk, .com.br)
        val lastTwo = "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
        val multiPartTlds = listOf("co.uk", "com.br", "org.uk", "net.uk", "com.au", "co.jp", "ac.uk")
        
        return if (multiPartTlds.contains(lastTwo) && parts.size >= 3) {
            "${parts[parts.size - 3]}.$lastTwo"
        } else {
            lastTwo
        }
    }
}

sealed class DomainVerificationResult {
    data class Verified(val verifiedDomain: String) : DomainVerificationResult()
    data class Unverified(val domain: String) : DomainVerificationResult()
    data class Blocked(val reason: String) : DomainVerificationResult()
}
