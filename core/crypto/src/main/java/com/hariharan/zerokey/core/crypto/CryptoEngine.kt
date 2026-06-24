package com.hariharan.zerokey.core.crypto

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class CryptoEngine {
    private val AES_MODE = "AES/GCM/NoPadding"
    private val IV_LENGTH = 12
    private val AUTH_TAG_LENGTH = 128

    fun encryptAesGcm(plaintext: ByteArray, key: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        val secretKey = SecretKeySpec(key, "AES")

        // Generate the IV explicitly with SecureRandom and pass it via
        // GCMParameterSpec, so behavior is identical on every JCE provider
        // (don't rely on the provider's default IV generation).
        val iv = ByteArray(IV_LENGTH).also { java.security.SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(AUTH_TAG_LENGTH, iv))
        val ciphertext = cipher.doFinal(plaintext)

        // Return IV + Ciphertext (matches decryptAesGcm, which reads the first 12 bytes as IV)
        return iv + ciphertext
    }

    fun decryptAesGcm(encryptedData: ByteArray, key: ByteArray): ByteArray {
        val iv = encryptedData.sliceArray(0 until IV_LENGTH)
        val ciphertext = encryptedData.sliceArray(IV_LENGTH until encryptedData.size)
        
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(AUTH_TAG_LENGTH, iv)
        val secretKey = SecretKeySpec(key, "AES")
        
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
        return cipher.doFinal(ciphertext)
    }
}
