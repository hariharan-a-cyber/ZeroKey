package com.hariharan.zerokey.security

import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Handles the secure derivation of encryption keys from user passwords.
 */
object KeyDerivationManager {

    private const val ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val ITERATIONS = 600000 
    private const val KEY_LENGTH = 256
    private const val SALT_LENGTH = 32

    /**
     * Generates a secure random salt.
     */
    fun generateSalt(): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(SALT_LENGTH)
        random.nextBytes(salt)
        return salt
    }

    /**
     * Derives a 256-bit AES key from a Master Password.
     * Secure Memory: The [password] CharArray should be cleared by the caller after use.
     */
    fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance(ALGORITHM)
        
        // Derive the key
        val derivedKeyBytes = factory.generateSecret(spec).encoded
        val secretKeySpec = SecretKeySpec(derivedKeyBytes, "AES")
        
        // Security: Clear the PBEKeySpec internal password buffer
        spec.clearPassword()
        
        return secretKeySpec
    }
}
