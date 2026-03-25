package com.hariharan.zerokey.core.security

import com.hariharan.zerokey.core.crypto.HmacEngine
import javax.crypto.SecretKey

/**
 * Handles HMAC signing and verification for vault integrity.
 * Relocated to core:security for architectural compliance.
 */
object VaultIntegrityManager {

    private val hmacEngine = HmacEngine()

    /**
     * Creates an HMAC-SHA256 signature for the given data.
     */
    fun sign(data: ByteArray, key: SecretKey): ByteArray {
        return hmacEngine.computeHmacSha256(data, key.encoded)
    }

    /**
     * Verifies the HMAC signature for the given data.
     * @return True if the signature is valid, false otherwise.
     */
    fun verify(data: ByteArray, signature: ByteArray, key: SecretKey): Boolean {
        val expectedSignature = sign(data, key)
        return hmacEngine.constantTimeEquals(signature, expectedSignature)
    }
}
