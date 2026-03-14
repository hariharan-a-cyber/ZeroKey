package com.hariharan.zerokey.securityanalytics

data class EntropyResult(
    val maskedPassword: String,
    val entropyBits: Float,
    val strength: PasswordStrength,
    val warnings: List<String>
)

enum class PasswordStrength { VERY_WEAK, WEAK, MODERATE, STRONG, VERY_STRONG }

enum class SecurityGrade(val label: String, val colorHex: String) {
    EXCELLENT("Excellent", "#2ECC71"),
    GOOD("Good", "#27AE60"),
    FAIR("Fair", "#F39C12"),
    POOR("Poor", "#E67E22"),
    CRITICAL("Critical", "#E74C3C")
}

data class VaultSecurityReport(
    val totalCredentials: Int,
    val weakPasswords: List<WeakPasswordItem>,
    val duplicateGroups: List<DuplicateGroup>,
    val breachedCredentials: List<BreachedItem>,
    val entropyResults: List<EntropyResult>,
    val generatedAt: Long = System.currentTimeMillis()
) {
    var securityScore: Int = 0
}

data class WeakPasswordItem(
    val credentialId: Int,
    val domain: String,
    val reason: String
)

data class DuplicateGroup(
    val passwordHash: String,    // HMAC of password — not plaintext
    val credentialIds: List<Int>,
    val domains: List<String>
)

data class BreachedItem(
    val credentialId: Int,
    val domain: String,
    val breachSource: String,
    val breachDate: String?
)
