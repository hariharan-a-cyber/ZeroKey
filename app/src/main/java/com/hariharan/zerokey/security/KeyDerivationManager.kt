package com.hariharan.zerokey.security

import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Phase 1: Key Derivation Manager.
 * Implements PBKDF2WithHmacSHA256 with 600,000 iterations.
 */
object KeyDerivationManager {

    private const val ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val ITERATIONS = 600000 
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = 16 // Phase 1 requirement: 16-byte salt

    /**
     * Generates a 16-byte secure random salt.
     */
    fun generateSalt(): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(SALT_LENGTH)
        random.nextBytes(salt)
        return salt
    }

    /**
     * Derives a 256-bit AES key from a Master Password.
     */
    fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance(ALGORITHM)
        
        val derivedKeyBytes = factory.generateSecret(spec).encoded
        val secretKeySpec = SecretKeySpec(derivedKeyBytes, "AES")
        
        // Security: Wipe the PBEKeySpec internal password buffer immediately
        spec.clearPassword()
        
        return secretKeySpec
    }
}
