package com.hariharan.zerokey.utils

import java.security.SecureRandom

/**
 * Production-Grade Password Utilities.
 */
object PasswordUtils {

    // Full ASCII character set for maximum entropy
    private const val UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
    private const val NUMBERS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>/?"

    /**
     * Generates a high-entropy cryptographically secure random password.
     * Minimum length 20 provides > 120 bits of entropy.
     */
    fun generatePassword(
        length: Int = 20,
        includeUppercase: Boolean = true,
        includeNumbers: Boolean = true,
        includeSymbols: Boolean = true
    ): String {
        val charPool = StringBuilder(LOWERCASE)
        if (includeUppercase) charPool.append(UPPERCASE)
        if (includeNumbers) charPool.append(NUMBERS)
        if (includeSymbols) charPool.append(SYMBOLS)

        val secureRandom = SecureRandom()
        val effectiveLength = length.coerceAtLeast(8)

        // Guarantee at least one character from each selected category.
        val required = mutableListOf<Char>()
        required.add(LOWERCASE[secureRandom.nextInt(LOWERCASE.length)])
        if (includeUppercase) required.add(UPPERCASE[secureRandom.nextInt(UPPERCASE.length)])
        if (includeNumbers) required.add(NUMBERS[secureRandom.nextInt(NUMBERS.length)])
        if (includeSymbols) required.add(SYMBOLS[secureRandom.nextInt(SYMBOLS.length)])

        val remaining = (1..(effectiveLength - required.size))
            .map { charPool[secureRandom.nextInt(charPool.length)] }
        val combined = (required + remaining).toMutableList()

        // Shuffle so the guaranteed chars aren't always at the start.
        for (i in combined.indices.reversed()) {
            val j = secureRandom.nextInt(i + 1)
            val tmp = combined[i]; combined[i] = combined[j]; combined[j] = tmp
        }
        return combined.joinToString("")
    }

    /**
     * Evaluates password strength using multiple heuristics.
     */
    fun calculateStrength(password: String): PasswordStrength {
        if (password.isEmpty()) return PasswordStrength.EMPTY
        
        var score = 0
        if (password.length >= 8) score++
        if (password.length >= 16) score++
        if (password.length >= 20) score++
        if (password.any { it.isUpperCase() }) score++
        if (password.any { it.isDigit() }) score++
        if (password.any { SYMBOLS.contains(it) }) score++

        return when {
            score <= 2 -> PasswordStrength.WEAK
            score <= 4 -> PasswordStrength.MEDIUM
            score == 5 -> PasswordStrength.STRONG
            else -> PasswordStrength.VERY_STRONG
        }
    }
}

enum class PasswordStrength {
    EMPTY, WEAK, MEDIUM, STRONG, VERY_STRONG
}
