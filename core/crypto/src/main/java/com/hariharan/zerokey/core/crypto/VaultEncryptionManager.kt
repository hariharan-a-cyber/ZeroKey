package com.hariharan.zerokey.core.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Handles just-in-time encryption/decryption of vault entries using Envelope Encryption.
 */
object VaultEncryptionManager {
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val AUTH_TAG_LENGTH = 128
    private const val IV_LENGTH = 12

    fun encrypt(data: ByteArray, key: SecretKey, aad: ByteArray? = null): EncryptedData {
        val cipher = Cipher.getInstance(AES_MODE)
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(iv)
        
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(AUTH_TAG_LENGTH, iv))
        aad?.let { cipher.updateAAD(it) }
        
        val cipherText = cipher.doFinal(data)
        return EncryptedData(cipherText, iv)
    }

    fun decrypt(encryptedData: EncryptedData, key: SecretKey, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(AUTH_TAG_LENGTH, encryptedData.iv))
        aad?.let { cipher.updateAAD(it) }
        
        return cipher.doFinal(encryptedData.cipherText)
    }
}
