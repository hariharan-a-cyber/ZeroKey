package com.hariharan.zerokey.core.crypto

import com.hariharan.zerokey.core.common.PrivacyLogger
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

/**
 * Phase 1: Key Derivation Manager.
 * Upgraded to Argon2id for modern, memory-hard key derivation.
 * 2026 Security Standards: 256MB RAM, 4 Iterations.
 */
object KeyDerivationManager {

    private val argon2Kt = Argon2Kt()
    
    // Argon2id configuration
    private val MODE = Argon2Mode.ARGON2_ID
    
    // Default 2026 Parameters
    const val DEFAULT_ITERATIONS = 4
    const val DEFAULT_MEMORY_KIB = 256 * 1024 // 256 MB
    const val DEFAULT_PARALLELISM = 4
    
    // Legacy Parameters (for backward compatibility)
    const val LEGACY_ITERATIONS = 3
    const val LEGACY_MEMORY_KIB = 64 * 1024 // 64 MB
    
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
     * Benchmarked for 2026 standards.
     */
    fun deriveKey(
        password: CharArray, 
        salt: ByteArray,
        iterations: Int = DEFAULT_ITERATIONS,
        memoryKib: Int = DEFAULT_MEMORY_KIB,
        parallelism: Int = DEFAULT_PARALLELISM
    ): SecretKeySpec {
        val startTime = System.currentTimeMillis()
        
        // Convert CharArray to ByteArray consistently without intermediate String
        val passwordBytes = ByteArray(password.size * 2)
        for (i in password.indices) {
            passwordBytes[i * 2] = (password[i].code ushr 8).toByte()
            passwordBytes[i * 2 + 1] = (password[i].code and 0xFF).toByte()
        }
        
        try {
            val result = argon2Kt.hash(
                mode = MODE,
                password = passwordBytes,
                salt = salt,
                tCostInIterations = iterations,
                mCostInKibibyte = memoryKib,
                parallelism = parallelism,
                hashLengthInBytes = HASH_LENGTH
            )
            
            val derivedKeyBytes = result.rawHashAsByteArray()
            val secretKeySpec = SecretKeySpec(derivedKeyBytes, "AES")
            
            val duration = System.currentTimeMillis() - startTime
            PrivacyLogger.i("Argon2", "Key derived in ${duration}ms (Memory: ${memoryKib / 1024}MB, Iterations: $iterations, Parallelism: $parallelism)")
            
            return secretKeySpec
        } finally {
            // Security: Wipe the temporary password byte array immediately
            passwordBytes.fill(0)
        }
    }
}
