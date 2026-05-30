package com.hariharan.zerokey.security

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
        
        // Let the provider generate a cryptographically strong random IV
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext)
        
        // Return IV + Ciphertext
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
