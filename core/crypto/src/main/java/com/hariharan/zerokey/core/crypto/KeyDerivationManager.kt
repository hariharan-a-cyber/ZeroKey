package com.hariharan.zerokey.core.crypto

import com.hariharan.zerokey.core.common.PrivacyLogger
import com.lambdapioneer.argon2kt.Argon2Kt
import com.lambdapioneer.argon2kt.Argon2Mode
import java.nio.CharBuffer
import java.nio.charset.StandardCharsets
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class KeyDerivationManager @Inject constructor() {

    companion object {
        const val SALT_LENGTH = 16
        // Version 4 is current. Versions 1-3 are kept for vaults created before
        // the UTF-8 fix — they keep unlocking with their original encoding until
        // the user changes their master password (which upgrades them to v4).
        const val LATEST_VERSION = 4
    }

    private data class ArgonConfig(
        val iterations: Int,
        val memoryKib: Int,
        val parallelism: Int
    )

    private val configs = mapOf(
        1 to ArgonConfig(3, 64 * 1024, 4),   // 64MB  legacy UTF-16BE
        2 to ArgonConfig(3, 128 * 1024, 4),  // 128MB legacy UTF-16BE
        3 to ArgonConfig(4, 256 * 1024, 4),  // 256MB legacy UTF-16BE
        4 to ArgonConfig(4, 256 * 1024, 4)   // 256MB UTF-8 (current standard)
    )

    fun deriveKey(password: CharArray, salt: ByteArray, version: Int = LATEST_VERSION): SecretKeySpec {
        val startTime = System.currentTimeMillis()
        val config = configs[version] ?: configs[1]!!

        // v4+ uses UTF-8 (standard, cross-platform). v1-v3 keep their old UTF-16BE
        // encoding so existing vaults stay unlockable.
        val passwordBytes: ByteArray = if (version >= 4) {
            val buf = StandardCharsets.UTF_8.encode(CharBuffer.wrap(password))
            ByteArray(buf.remaining()).also { buf.get(it) }
        } else {
            ByteArray(password.size * 2).also { bytes ->
                for (i in password.indices) {
                    bytes[i * 2] = (password[i].code ushr 8).toByte()
                    bytes[i * 2 + 1] = (password[i].code and 0xFF).toByte()
                }
            }
        }

        try {
            val argon2 = Argon2Kt()
            val result = argon2.hash(
                mode = Argon2Mode.ARGON2_ID,
                password = passwordBytes,
                salt = salt,
                tCostInIterations = config.iterations,
                mCostInKibibyte = config.memoryKib,
                parallelism = config.parallelism,
                hashLengthInBytes = 32
            )
            val derivedBytes = result.rawHashAsByteArray()
            val elapsed = System.currentTimeMillis() - startTime
            PrivacyLogger.d("KDF", "Argon2id v$version derived in ${elapsed}ms")
            return SecretKeySpec(derivedBytes, "AES")
        } finally {
            passwordBytes.fill(0)
        }
    }

    fun generateSalt(): ByteArray {
        val salt = ByteArray(SALT_LENGTH)
        SecureRandom().nextBytes(salt)
        return salt
    }
}
