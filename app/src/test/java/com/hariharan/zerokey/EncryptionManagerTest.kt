package com.hariharan.zerokey

import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.crypto.EncryptedData
import org.junit.Assert.*
import org.junit.Test
import javax.crypto.spec.SecretKeySpec

class EncryptionManagerTest {

    private val encryptionManager = EncryptionManager()
    private val testKey = SecretKeySpec(ByteArray(32) { 1.toByte() }, "AES")
    private val plaintext = "Hello ZeroKey".toByteArray()

    @Test
    fun `encryptWithKey then decryptWithKey returns original plaintext`() {
        val encrypted = encryptionManager.encryptWithKey(plaintext, testKey)
        val decrypted = encryptionManager.decryptWithKey(encrypted, testKey)
        
        assertArrayEquals("Decrypted data must match original plaintext", plaintext, decrypted)
    }

    @Test(expected = Exception::class)
    fun `decryptWithKey with wrong key throws exception`() {
        val wrongKey = SecretKeySpec(ByteArray(32) { 2.toByte() }, "AES")
        val encrypted = encryptionManager.encryptWithKey(plaintext, testKey)
        
        // This should throw because of AEAD (GCM) integrity check
        encryptionManager.decryptWithKey(encrypted, wrongKey)
    }

    @Test
    fun `each encryption produces a unique IV`() {
        val encrypted1 = encryptionManager.encryptWithKey(plaintext, testKey)
        val encrypted2 = encryptionManager.encryptWithKey(plaintext, testKey)
        
        assertFalse("IVs must be unique for each call", encrypted1.iv.contentEquals(encrypted2.iv))
    }

    @Test(expected = Exception::class)
    fun `AAD mismatch causes decryption failure`() {
        val aad1 = "context-A".toByteArray()
        val aad2 = "context-B".toByteArray()
        
        val encrypted = encryptionManager.encryptWithKey(plaintext, testKey, aad1)
        
        // Should throw because AAD is part of the tag calculation
        encryptionManager.decryptWithKey(encrypted, testKey, aad2)
    }
}
