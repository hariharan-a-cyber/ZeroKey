package com.hariharan.zerokey

import com.hariharan.zerokey.core.crypto.KeyDerivationManager
import org.junit.Assert.*
import org.junit.Test

class KeyDerivationManagerTest {

    private val manager = KeyDerivationManager()
    private val testPassword = "password123".toCharArray()
    private val testSalt = ByteArray(16) { 0x01.toByte() }

    @Test
    fun `deriveKey with same password and salt returns identical key bytes`() {
        // Use copyOf because manager zeros out the input array
        val key1 = manager.deriveKey(testPassword.copyOf(), testSalt, version = 1)
        val key2 = manager.deriveKey(testPassword.copyOf(), testSalt, version = 1)
        
        assertArrayEquals("Same inputs must produce identical keys", key1.encoded, key2.encoded)
    }

    @Test
    fun `deriveKey with different salt returns different key bytes`() {
        val salt2 = ByteArray(16) { 0x02.toByte() }
        
        val key1 = manager.deriveKey(testPassword.copyOf(), testSalt, version = 1)
        val key2 = manager.deriveKey(testPassword.copyOf(), salt2, version = 1)
        
        assertFalse("Different salts must produce different keys", key1.encoded.contentEquals(key2.encoded))
    }

    @Test
    fun `password CharArray is zeroed after derivation`() {
        val password = charArrayOf('s', 'e', 'c', 'r', 'e', 't')
        
        manager.deriveKey(password, testSalt, version = 1)
        
        val isZeroed = password.all { it == '\u0000' }
        assertTrue("Input password CharArray must be zeroed for security", isZeroed)
    }

    @Test
    fun `all versions produce 32-byte keys`() {
        val keyV1 = manager.deriveKey(testPassword.copyOf(), testSalt, version = 1)
        val keyV2 = manager.deriveKey(testPassword.copyOf(), testSalt, version = 2)
        val keyV3 = manager.deriveKey(testPassword.copyOf(), testSalt, version = 3)
        
        assertEquals("V1 key must be 32 bytes", 32, keyV1.encoded.size)
        assertEquals("V2 key must be 32 bytes", 32, keyV2.encoded.size)
        assertEquals("V3 key must be 32 bytes", 32, keyV3.encoded.size)
    }
}
