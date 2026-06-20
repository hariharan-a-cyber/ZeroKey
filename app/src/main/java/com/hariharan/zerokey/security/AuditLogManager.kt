package com.hariharan.zerokey.security

import android.util.Base64
import com.hariharan.zerokey.core.common.PrivacyLogger
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.database.AuditLogDao
import com.hariharan.zerokey.core.database.AuditLogEntity
import com.hariharan.zerokey.core.security.MasterPasswordManager
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AuditLogManager @Inject constructor(
    private val auditLogDao: AuditLogDao,
    private val masterPasswordManager: MasterPasswordManager,
    private val encryptionManager: EncryptionManager
) {
    enum class EventType {
        VAULT_UNLOCKED, VAULT_LOCKED, VAULT_EXPORTED,
        PASSWORD_ADDED, PASSWORD_VIEWED, PASSWORD_COPIED, PASSWORD_DELETED,
        SETTINGS_CHANGED, RECOVERY_KEY_GENERATED, MASTER_PASSWORD_CHANGED,
        DEVICE_REVOKED, AUTOFILL_USED, LOGIN_FAILURE
    }

    /**
     * Audit details often contain service names. We encrypt them with the vault
     * key while the vault is unlocked; if it's locked we record a redaction marker
     * instead of leaking plaintext.
     */
    private fun encryptDetails(details: String): String {
        val vk = masterPasswordManager.getVaultKey() ?: return "[locked-redacted]"
        return try {
            val enc = encryptionManager.encryptWithKey(details.toByteArray(Charsets.UTF_8), vk)
            "v1:" + Base64.encodeToString(enc.iv, Base64.NO_WRAP) +
                ":" + Base64.encodeToString(enc.cipherText, Base64.NO_WRAP)
        } catch (e: Exception) {
            "[encryption-error]"
        }
    }

    fun decryptDetails(stored: String): String {
        if (!stored.startsWith("v1:")) return stored
        val parts = stored.removePrefix("v1:").split(":")
        if (parts.size != 2) return "[corrupted]"
        val vk = masterPasswordManager.getVaultKey() ?: return "[locked]"
        return try {
            val plain = encryptionManager.decryptWithKey(
                EncryptedData(
                    Base64.decode(parts[1], Base64.NO_WRAP),
                    Base64.decode(parts[0], Base64.NO_WRAP)
                ),
                vk
            )
            String(plain, Charsets.UTF_8)
        } catch (e: Exception) {
            "[decryption-error]"
        }
    }

    suspend fun log(eventType: EventType, details: String) {
        try {
            auditLogDao.insertLog(AuditLogEntity(
                eventType = eventType.name,
                details = encryptDetails(details)
            ))
        } catch (e: Exception) {
            PrivacyLogger.e("AuditLog", "Failed to write log: ${e.message}")
        }
    }

    suspend fun getAllLogs(): List<AuditLogEntity> = auditLogDao.getAllLogs()

    suspend fun clearLogs() = auditLogDao.clearLogs()
}
