package com.hariharan.zerokey.core.crypto

import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class HmacEngine {
    companion object {
        private const val ALGORITHM = "HmacSHA256"
    }

    fun computeHmacSha256(data: ByteArray, key: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        val secretKey = SecretKeySpec(key, ALGORITHM)
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    /**
     * Derives a distinct 32-byte subkey from a base key for a given purpose label
     * (HKDF-Expand, single block). Lets us use separate keys for encryption vs MAC.
     */
    fun deriveSubKey(baseKey: ByteArray, label: String): ByteArray {
        return computeHmacSha256((label + "\u0001").toByteArray(Charsets.UTF_8), baseKey)
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        return MessageDigest.isEqual(a, b)
    }
}
