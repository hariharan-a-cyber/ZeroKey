package com.hariharan.zerokey.data.database

import androidx.room.Entity
import androidx.room.PrimaryKey
import kotlinx.serialization.Serializable

@Serializable
@Entity(tableName = "passwords")
data class PasswordEntity(
    @PrimaryKey(autoGenerate = true)
    val id: Int = 0,
    val encryptedServiceName: String,
    val serviceNameIv: String,
    val encryptedUsername: String,
    val usernameIv: String,
    val encryptedPassword: String,
    val passwordIv: String,
    val encryptedNotes: String? = null,
    val notesIv: String? = null,
    val isFavorite: Boolean = false,
    val createdAt: Long = System.currentTimeMillis(),
    val lastModified: Long = System.currentTimeMillis(),
    val isDeleted: Boolean = false,
    
    // Phase 2 Columns
    val passkeyCredentialId: String? = null,
    val lastBreachCheck: Long = 0,
    val breachFound: Boolean = false
)

@Serializable
@Entity(tableName = "passkey_records")
data class PasskeyEntity(
    @PrimaryKey
    val credentialId: String,
    val domain: String,
    val userId: String,
    val username: String,
    val publicKey: String,
    val createdAt: Long = System.currentTimeMillis(),
    val lastUsedAt: Long? = null,
    val syncId: String? = null
)

@Serializable
@Entity(tableName = "security_events")
data class SecurityEventEntity(
    @PrimaryKey
    val id: String,
    val eventType: String,
    val domain: String? = null,
    val packageName: String? = null,
    val reason: String? = null,
    val severity: String,
    val timestamp: Long = System.currentTimeMillis(),
    val resolved: Boolean = false
)

@Serializable
@Entity(tableName = "incoming_shares")
data class SharedCredentialEntity(
    @PrimaryKey
    val id: String,
    val senderUserId: String,
    val encryptedPayload: String,
    val ephemeralSenderPublicKey: String,
    val receivedAt: Long = System.currentTimeMillis(),
    val expiresAt: Long,
    val status: String = "PENDING",
    val decryptedCredentialId: Int? = null
)

@Serializable
@Entity(tableName = "emergency_access_config")
data class EmergencyAccessEntity(
    @PrimaryKey
    val ownerId: String,
    val contactUserId: String,
    val contactEmail: String,
    val encryptedEmergencyVault: String,
    val inactivityThresholdMs: Long,
    val lastOwnerActivity: Long,
    val status: String = "CONFIGURED",
    val createdAt: Long = System.currentTimeMillis(),
    val requestedAt: Long? = null,
    val approveAt: Long? = null
)

@Serializable
@Entity(tableName = "vault_sync_metadata")
data class SyncMetadataEntity(
    @PrimaryKey
    val userId: String,
    val deviceId: String,
    val lastPushedAt: Long? = null,
    val lastPulledAt: Long? = null,
    val localVersion: Int = 0,
    val remoteVersion: Int? = null,
    val syncStatus: String = "IDLE",
    val privacyMode: Boolean = false
)

@Serializable
@Entity(tableName = "security_score_history")
data class SecurityScoreHistoryEntity(
    @PrimaryKey
    val id: String,
    val userId: String,
    val score: Int,
    val grade: String,
    val weakCount: Int = 0,
    val duplicateCount: Int = 0,
    val breachCount: Int = 0,
    val recordedAt: Long = System.currentTimeMillis()
)
