package com.hariharan.zerokey.security

import java.security.SecureRandom

/**
 * Phase 5: Secure Password Generator.
 * Uses SecureRandom for cryptographic strength.
 */
object PasswordGenerator {

    private val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".toCharArray()
    private val LOWER = "abcdefghijklmnopqrstuvwxyz".toCharArray()
    private val DIGITS = "0123456789".toCharArray()
    private val SYMBOLS = "!@#$%^&*()-_=+[]{}|;:,.<>?".toCharArray()

    fun generate(
        length: Int = 20,
        includeUpper: Boolean = true,
        includeDigits: Boolean = true,
        includeSymbols: Boolean = true
    ): String {
        val charPool = mutableListOf<Char>()
        charPool.addAll(LOWER.toList())
        if (includeUpper) charPool.addAll(UPPER.toList())
        if (includeDigits) charPool.addAll(DIGITS.toList())
        if (includeSymbols) charPool.addAll(SYMBOLS.toList())

        val random = SecureRandom()
        val password = CharArray(length)
        
        for (i in 0 until length) {
            password[i] = charPool[random.nextInt(charPool.size)]
        }
        
        val result = String(password)
        // Wipe local buffer
        password.fill(' ')
        return result
    }
}
