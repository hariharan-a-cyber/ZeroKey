package com.hariharan.zerokey.security

import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Handles HMAC signing and verification for vault integrity.
 */
object VaultIntegrityManager {

    private const val ALGORITHM = "HmacSHA256"

    /**
     * Creates an HMAC-SHA256 signature for the given data.
     */
    fun sign(data: ByteArray, key: SecretKey): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(key)
        return mac.doFinal(data)
    }

    /**
     * Verifies the HMAC signature for the given data.
     * @return True if the signature is valid, false otherwise.
     */
    fun verify(data: ByteArray, signature: ByteArray, key: SecretKey): Boolean {
        val expectedSignature = sign(data, key)
        return signature.contentEquals(expectedSignature)
    }
}
