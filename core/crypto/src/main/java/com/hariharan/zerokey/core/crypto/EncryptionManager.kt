package com.hariharan.zerokey.core.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import com.hariharan.zerokey.core.common.PrivacyLogger
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Enhanced Encryption Manager for ZeroKey.
 * Implements AES-256-GCM with Associated Authenticated Data (AAD) support.
 * Supports Hardware-backed keys (TEE) and attempts to use StrongBox (Secure Element) if available.
 */
object EncryptionManager {

    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "ZeroKeyRootKey"
    private const val AES_MODE = "AES/GCM/NoPadding"
    private const val IV_LENGTH = 12 
    private const val AUTH_TAG_LENGTH = 128

    fun init() {
        generateRootKeyIfNeeded()
    }

    private fun generateRootKeyIfNeeded() {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (!keyStore.containsAlias(KEY_ALIAS)) {
            try {
                generateAesKey(KEY_ALIAS, useStrongBox = true)
                PrivacyLogger.i("EncryptionManager", "Root key generated in StrongBox")
            } catch (e: Exception) {
                PrivacyLogger.w("EncryptionManager", "StrongBox unavailable, falling back to TEE: ${e.message}")
                generateAesKey(KEY_ALIAS, useStrongBox = false)
                PrivacyLogger.i("EncryptionManager", "Root key generated in TEE")
            }
        }
    }

    private fun generateAesKey(alias: String, useStrongBox: Boolean) {
        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(useStrongBox)
        }

        keyGenerator.init(builder.build())
        keyGenerator.generateKey()
    }

    private fun getRootKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return keyStore.getKey(KEY_ALIAS, null) as SecretKey
    }

    fun encryptWithKey(data: ByteArray, key: SecretKey, aad: ByteArray? = null): EncryptedData {
        val cipher = Cipher.getInstance(AES_MODE)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        aad?.let { cipher.updateAAD(it) }
        val ciphertext = cipher.doFinal(data)
        val iv = cipher.iv
        return EncryptedData(ciphertext, iv)
    }

    fun decryptWithKey(encryptedData: EncryptedData, key: SecretKey, aad: ByteArray? = null): ByteArray {
        val cipher = Cipher.getInstance(AES_MODE)
        val spec = GCMParameterSpec(AUTH_TAG_LENGTH, encryptedData.iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)
        aad?.let { cipher.updateAAD(it) }
        return cipher.doFinal(encryptedData.cipherText)
    }

    fun encryptWithRootKey(data: ByteArray, aad: ByteArray? = null): EncryptedData {
        return encryptWithKey(data, getRootKey(), aad)
    }

    fun decryptWithRootKey(encryptedData: EncryptedData, aad: ByteArray? = null): ByteArray {
        return decryptWithKey(encryptedData, getRootKey(), aad)
    }
}

data class EncryptedData(
    val cipherText: ByteArray,
    val iv: ByteArray
)
