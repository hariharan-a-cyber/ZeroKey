package com.hariharan.zerokey

import com.hariharan.zerokey.core.common.PrivacyLogger
import org.junit.Assert.*
import org.junit.Test
import java.lang.reflect.Field

class PrivacyLoggerTest {

    @Test
    fun `masking is consistent within the same rotation period`() {
        val input = "example.com"
        val hash1 = PrivacyLogger.mask(input)
        val hash2 = PrivacyLogger.mask(input)
        
        assertEquals("Hashes should be identical for same input", hash1, hash2)
    }

    @Test
    fun `masking is different for different inputs`() {
        val hash1 = PrivacyLogger.mask("domain1.com")
        val hash2 = PrivacyLogger.mask("domain2.com")
        
        assertNotEquals("Hashes should be different for different inputs", hash1, hash2)
    }

    @Test
    fun `masking handles null and blank values`() {
        assertEquals("null", PrivacyLogger.mask(null))
        assertEquals("empty", PrivacyLogger.mask(""))
        assertEquals("empty", PrivacyLogger.mask("   "))
    }

    @Test
    fun `sanitization removes emails and IPs`() {
        val raw = "Error for user@example.com at 192.168.1.1"
        val sanitized = PrivacyLogger.sanitizeError(raw)
        
        assertFalse("Should not contain email", sanitized.contains("user@example.com"))
        assertFalse("Should not contain IP", sanitized.contains("192.168.1.1"))
        assertTrue("Should contain masked_email", sanitized.contains("masked_email"))
        assertTrue("Should contain masked_ip", sanitized.contains("masked_ip"))
    }

    @Test
    fun `sanitization removes long IDs`() {
        val raw = "Failed for ID: a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"
        val sanitized = PrivacyLogger.sanitizeError(raw)
        
        assertFalse("Should not contain long ID", sanitized.contains("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"))
        assertTrue("Should contain masked_id", sanitized.contains("masked_id"))
    }

    @Test
    fun `masking changes when key is rotated`() {
        val input = "persistent-domain.com"
        val hashBefore = PrivacyLogger.mask(input)

        // Force rotation using reflection for testing
        rotateKeyManually()

        val hashAfter = PrivacyLogger.mask(input)
        
        assertNotEquals("Hash must change after key rotation", hashBefore, hashAfter)
    }

    private fun rotateKeyManually() {
        try {
            val field: Field = PrivacyLogger::class.java.getDeclaredField("lastRotationTime")
            field.isAccessible = true
            // Set last rotation time to 25 hours ago
            field.set(PrivacyLogger, System.currentTimeMillis() - (25 * 60 * 60 * 1000L))
        } catch (e: Exception) {
            fail("Failed to rotate key via reflection: ${e.message}")
        }
    }
}
