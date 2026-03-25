package com.hariharan.zerokey.data.model

import com.hariharan.zerokey.data.database.PasswordEntity
import com.hariharan.zerokey.security.EncryptedData
import com.hariharan.zerokey.security.EncryptionManager
import com.hariharan.zerokey.security.MasterPasswordManager
import android.util.Base64
import android.util.Log
import kotlinx.serialization.Serializable
import kotlinx.serialization.Transient

/**
 * Enhanced PasswordItem with Lazy Decryption.
 * Only decrypts fields when explicitly accessed to improve performance in large vaults.
 */
@Serializable
class PasswordItem(
    val id: Int,
    @Transient
    private val encryptedEntity: PasswordEntity? = null,
    // Fallback for creation/manual items
    private val initialServiceName: String = "",
    private val initialUsername: String = "",
    private val initialPassword: String = "",
    private val initialNotes: String? = null,
    val isFavorite: Boolean = false,
    val createdAt: Long = encryptedEntity?.createdAt ?: System.currentTimeMillis()
) {
    // Decryption cache
    @Transient
    private var _serviceName: String? = if (encryptedEntity == null) initialServiceName else null
    @Transient
    private var _username: String? = if (encryptedEntity == null) initialUsername else null
    @Transient
    private var _password: String? = if (encryptedEntity == null) initialPassword else null
    @Transient
    private var _notes: String? = if (encryptedEntity == null) initialNotes else null

    val serviceName: String
        get() {
            if (_serviceName == null && encryptedEntity != null) {
                _serviceName = try {
                    decryptField(encryptedEntity.encryptedServiceName, encryptedEntity.serviceNameIv, encryptedEntity.createdAt)
                } catch (e: Exception) {
                    Log.e("PasswordItem", "Decryption failed for serviceName", e)
                    "[Decryption Error]"
                }
            }
            return _serviceName ?: ""
        }

    val username: String
        get() {
            if (_username == null && encryptedEntity != null) {
                _username = try {
                    decryptField(encryptedEntity.encryptedUsername, encryptedEntity.usernameIv, encryptedEntity.createdAt)
                } catch (e: Exception) {
                    Log.e("PasswordItem", "Decryption failed for username", e)
                    "unknown"
                }
            }
            return _username ?: ""
        }

    val password: String
        get() {
            if (_password == null && encryptedEntity != null) {
                _password = try {
                    decryptField(encryptedEntity.encryptedPassword, encryptedEntity.passwordIv, encryptedEntity.createdAt)
                } catch (e: Exception) {
                    Log.e("PasswordItem", "Decryption failed for password", e)
                    ""
                }
            }
            return _password ?: ""
        }

    val notes: String?
        get() {
            if (_notes == null && encryptedEntity != null && encryptedEntity.encryptedNotes != null) {
                _notes = try {
                    decryptField(encryptedEntity.encryptedNotes, encryptedEntity.notesIv!!, encryptedEntity.createdAt)
                } catch (e: Exception) {
                    Log.e("PasswordItem", "Decryption failed for notes", e)
                    null
                }
            }
            return _notes
        }

    fun toEntity(): PasswordEntity {
        return encryptedEntity ?: throw IllegalStateException("Cannot convert non-persistent item to entity")
    }

    private fun decryptField(ciphertext: String, iv: String, createdAt: Long): String {
        val vaultKey = MasterPasswordManager.getVaultKey() 
            ?: throw IllegalStateException("Vault locked")
        
        val aad = "timestamp:$createdAt".toByteArray()
        val data = EncryptedData(Base64.decode(ciphertext, Base64.NO_WRAP), Base64.decode(iv, Base64.NO_WRAP))
        
        return EncryptionManager.decryptWithKey(data, vaultKey, aad).decodeToString()
    }
}
