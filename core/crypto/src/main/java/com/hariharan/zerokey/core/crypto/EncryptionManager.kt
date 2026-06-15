package com.hariharan.zerokey.core.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import com.hariharan.zerokey.core.common.PrivacyLogger
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Enhanced Encryption Manager for ZeroKey.
 * Implements AES-256-GCM with Associated Authenticated Data (AAD) support.
 * Supports Hardware-backed keys (TEE) and attempts to use StrongBox (Secure Element) if available.
 */
@Singleton
class EncryptionManager @Inject constructor() {

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEY_ALIAS = "ZeroKeyRootKey"
        private const val AES_MODE = "AES/GCM/NoPadding"
        private const val IV_LENGTH = 12 
        private const val AUTH_TAG_LENGTH = 128
    }

    enum class KeySecurityLevel { SOFTWARE, TEE, STRONGBOX }

    fun init() {
        generateRootKeyIfNeeded()
    }

    fun getKeySecurityLevel(): KeySecurityLevel {
        return try {
            val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = keyStore.getKey(KEY_ALIAS, null) as? SecretKey ?: return KeySecurityLevel.SOFTWARE
            val factory = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeySecurityLevel.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeySecurityLevel.TEE
                    else -> KeySecurityLevel.SOFTWARE
                }
            } else if (keyInfo.isInsideSecureHardware) {
                KeySecurityLevel.TEE
            } else {
                KeySecurityLevel.SOFTWARE
            }
        } catch (e: Exception) {
            KeySecurityLevel.SOFTWARE
        }
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
