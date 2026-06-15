package com.hariharan.zerokey.core.crypto

import com.hariharan.zerokey.core.common.PrivacyLogger
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Phase 1: Key Derivation Manager.
 * Upgraded to Argon2id for modern, memory-hard key derivation.
 * 2026 Security Standards: 256MB RAM, 4 Iterations.
 */
@Singleton
class KeyDerivationManager @Inject constructor() {

    private val argon2Kt = Argon2Kt()
    
    companion object {
        // Argon2id configuration
        private val MODE = Argon2Mode.ARGON2_ID
        private const val HASH_LENGTH = 32 // 256 bits
        private const val SALT_LENGTH = 16

        const val LATEST_VERSION = 3
    }

    private data class ArgonConfig(
        val iterations: Int,
        val memoryKib: Int,
        val parallelism: Int
    )

    private val configs = mapOf(
        1 to ArgonConfig(3, 64 * 1024, 4),    // 64MB
        2 to ArgonConfig(3, 128 * 1024, 4),   // 128MB
        3 to ArgonConfig(4, 256 * 1024, 4)    // 256MB (2026 Standard)
    )

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
    fun deriveKey(password: CharArray, salt: ByteArray, version: Int = LATEST_VERSION): SecretKeySpec {
        val startTime = System.currentTimeMillis()
        val config = configs[version] ?: configs[1]!!

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
                tCostInIterations = config.iterations,
                mCostInKibibyte = config.memoryKib,
                parallelism = config.parallelism,
                hashLengthInBytes = HASH_LENGTH
            )
            
            val derivedKeyBytes = result.rawHashAsByteArray()
            
            val duration = System.currentTimeMillis() - startTime
            PrivacyLogger.i("Argon2", "Key derived (v$version) in ${duration}ms (Memory: ${config.memoryKib / 1024}MB, Iterations: ${config.iterations})")

            return SecretKeySpec(derivedKeyBytes, "AES")
        } finally {
            // Security: Wipe the password arrays immediately
            passwordBytes.fill(0)
            password.fill('\u0000')
        }
    }
}
