package com.hariharan.zerokey.securityanalytics

import kotlin.math.log2

class PasswordEntropyAnalyzer {

    private val COMMON_PATTERNS = listOf(
        "password", "123456", "qwerty", "abc123", "letmein",
        "admin", "welcome", "monkey", "dragon", "master"
    )

    fun analyze(password: String): EntropyResult {
        if (password.isEmpty()) return EntropyResult(password, 0f, PasswordStrength.VERY_WEAK, emptyList())

        val poolSize = computePoolSize(password)
        val rawEntropy = password.length * log2(poolSize.toDouble()).toFloat()

        val warnings = mutableListOf<String>()

        // Pattern penalties
        val adjustedEntropy = when {
            hasCommonPattern(password) -> {
                warnings.add("Contains common password pattern")
                rawEntropy * 0.3f
            }
            hasKeyboardWalk(password) -> {
                warnings.add("Contains keyboard walk sequence")
                rawEntropy * 0.5f
            }
            hasRepeatedChars(password) -> {
                warnings.add("Contains repeated character sequences")
                rawEntropy * 0.7f
            }
            else -> rawEntropy
        }

        // Short passwords can never be "strong" regardless of character variety.
        val lengthCappedEntropy = when {
            password.length < 8 -> minOf(adjustedEntropy, 35f)
            password.length < 12 -> minOf(adjustedEntropy, 70f)
            else -> adjustedEntropy
        }
        val strength = strengthFromEntropy(lengthCappedEntropy)
        return EntropyResult(password.take(3) + "***", lengthCappedEntropy, strength, warnings)
    }

    private fun computePoolSize(password: String): Int {
        var pool = 0
        if (password.any { it.isLowerCase() }) pool += 26
        if (password.any { it.isUpperCase() }) pool += 26
        if (password.any { it.isDigit() }) pool += 10
        if (password.any { !it.isLetterOrDigit() }) pool += 32
        return pool.coerceAtLeast(1)
    }

    private fun hasCommonPattern(password: String): Boolean {
        val lower = password.lowercase()
        // Only penalize if a common word makes up most of the password (not just appears in a long random one).
        return COMMON_PATTERNS.any { lower.contains(it) && it.length >= password.length - 3 }
    }

    private fun hasKeyboardWalk(password: String): Boolean {
        val walks = listOf("qwerty", "asdfgh", "zxcvbn", "123456", "234567")
        return walks.any { password.lowercase().contains(it) }
    }

    private fun hasRepeatedChars(password: String): Boolean {
        return password.length > 3 && password.windowed(3).any { w -> w.all { it == w[0] } }
    }

    private fun strengthFromEntropy(entropy: Float): PasswordStrength = when {
        entropy >= 80 -> PasswordStrength.VERY_STRONG
        entropy >= 60 -> PasswordStrength.STRONG
        entropy >= 40 -> PasswordStrength.MODERATE
        entropy >= 25 -> PasswordStrength.WEAK
        else          -> PasswordStrength.VERY_WEAK
    }
}
