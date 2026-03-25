package com.hariharan.zerokey.security

import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

/**
 * Phase 1: Key Derivation Manager.
 * Upgraded to Argon2id for modern, memory-hard key derivation.
 * Recommended parameters for 2026 security standards.
 */
object KeyDerivationManager {

    private val argon2Kt = Argon2Kt()
    
    // Argon2id configuration
    private val MODE = Argon2Mode.ARGON2_ID
    private const val ITERATIONS = 3
    private const val MEMORY_KIB = 64 * 1024 // 64 MB
    private const val PARALLELISM = 4
    private const val HASH_LENGTH = 32 // 256 bits
    
    private const val SALT_LENGTH = 16

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
     * Derives a 256-bit AES key from a Master Password using Argon2id.
     */
    fun deriveKey(password: CharArray, salt: ByteArray): SecretKeySpec {
        // Convert CharArray to ByteArray for Argon2
        val passwordBytes = password.map { it.code.toByte() }.toByteArray()
        
        val result = argon2Kt.hash(
            mode = MODE,
            password = passwordBytes,
            salt = salt,
            tCostInIterations = ITERATIONS,
            mCostInKibibyte = MEMORY_KIB,
            parallelism = PARALLELISM,
            hashLengthInBytes = HASH_LENGTH
        )
        
        val derivedKeyBytes = result.rawHashAsByteArray()
        val secretKeySpec = SecretKeySpec(derivedKeyBytes, "AES")
        
        // Security: Wipe the temporary password byte array
        passwordBytes.fill(0)
        
        return secretKeySpec
    }
}
