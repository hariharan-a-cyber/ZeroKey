package com.hariharan.zerokey.security

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Handles the encryption and decryption of the entire vault for sync/backup.
 * Implements Zero-Knowledge security by using a key derived from the Master Password.
 */
object VaultEncryptionManager {

    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val AUTH_TAG_LENGTH = 128
    private const val IV_LENGTH = 12

    /**
     * Encrypts the vault data using a derived Master Key.
     */
    fun encryptVault(plainText: String, masterKey: SecretKey): EncryptedData {
        val cipher = Cipher.getInstance(AES_MODE)
        val iv = ByteArray(IV_LENGTH)
        SecureRandom().nextBytes(iv)
        val spec = GCMParameterSpec(AUTH_TAG_LENGTH, iv)
        
        cipher.init(Cipher.ENCRYPT_MODE, masterKey, spec)
        val cipherText = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))
        
        return EncryptedData(cipherText, iv)
    }

    /**
     * Decrypts the vault data using a derived Master Key and the provided IV.
     */
    fun decryptVault(encryptedData: EncryptedData, masterKey: SecretKey): String {
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(AUTH_TAG_LENGTH, encryptedData.iv)
        
        cipher.init(Cipher.DECRYPT_MODE, masterKey, spec)
        val decryptedBytes = cipher.doFinal(encryptedData.cipherText)
        
        val result = String(decryptedBytes, Charsets.UTF_8)
        
        // Secure Memory: The resulting string should be converted to CharArray 
        // by the caller and cleared after use.
        return result
    }
}
