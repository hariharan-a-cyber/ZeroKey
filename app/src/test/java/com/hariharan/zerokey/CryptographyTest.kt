package com.hariharan.zerokey

import com.hariharan.zerokey.security.EncryptionManager
import com.hariharan.zerokey.security.KeyDerivationManager
import org.junit.Assert.*
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class CryptographyTest {

    private val testKey = SecretKeySpec(ByteArray(32) { 1.toByte() }, "AES")

    @Test
    fun `Argon2 derivation is deterministic for same version`() {
        val password = "password123".toCharArray()
        val salt = ByteArray(16) { 0x01.toByte() }
        
        val key1 = KeyDerivationManager.deriveKey(password, salt, version = 1)
        val key2 = KeyDerivationManager.deriveKey(password, salt, version = 1)
        
        assertArrayEquals("Same version must produce same key", key1.encoded, key2.encoded)
    }

    @Test
    fun `Argon2 derivation differs between versions`() {
        val password = "password123".toCharArray()
        val salt = ByteArray(16) { 0x01.toByte() }
        
        val keyV1 = KeyDerivationManager.deriveKey(password, salt, version = 1)
        val keyV2 = KeyDerivationManager.deriveKey(password, salt, version = 2)
        val keyV3 = KeyDerivationManager.deriveKey(password, salt, version = 3)
        
        assertFalse("V1 and V2 keys must differ", keyV1.encoded.contentEquals(keyV2.encoded))
        assertFalse("V2 and V3 keys must differ", keyV2.encoded.contentEquals(keyV3.encoded))
    }

    @Test
    fun `IV is unique for every encryption call`() {
        val plaintext = "Sensitive data".toByteArray()
        
        val result1 = EncryptionManager.encryptWithKey(plaintext, testKey)
        val result2 = EncryptionManager.encryptWithKey(plaintext, testKey)
        
        assertFalse("IVs must be different", result1.iv.contentEquals(result2.iv))
        assertFalse("Ciphertexts must be different", result1.cipherText.contentEquals(result2.cipherText))
    }

    @Test
    fun `AAD mismatch prevents decryption`() {
        val plaintext = "Secret message"
        val aad1 = "context-A".toByteArray()
        val aad2 = "context-B".toByteArray()
        
        val encrypted = EncryptionManager.encryptWithKey(plaintext.toByteArray(), testKey, aad1)
        
        // Decrypt with correct AAD
        val decrypted = EncryptionManager.decryptWithKey(encrypted, testKey, aad1)
        assertEquals(plaintext, decrypted.decodeToString())
        
        // Attempt decrypt with wrong AAD (should throw exception)
        try {
            EncryptionManager.decryptWithKey(encrypted, testKey, aad2)
            fail("Decryption should have failed due to AAD mismatch")
        } catch (e: Exception) {
            // Expected: AEAD integrity check failed
        }
    }
}
