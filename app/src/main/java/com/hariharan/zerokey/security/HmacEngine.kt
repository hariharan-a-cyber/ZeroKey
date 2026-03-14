package com.hariharan.zerokey.security

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

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        return MessageDigest.isEqual(a, b)
    }
}
