package com.hariharan.zerokey.core.database

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
    val passkeyCredentialId: String? = null,
    val lastBreachCheck: Long = 0L,
    val breachFound: Boolean = false,
    val recordUid: String = "",      // Required. Backfilled in MIGRATION_5_6.
    val encryptionVersion: Int = 1,
    val schemaVersion: Int = 6       // Match repository default — no AAD drift.
)

@Serializable
@Entity(tableName = "passkey_records")
data class PasskeyEntity(
    @PrimaryKey val credentialId: String,
    val domain: String,
    val userId: String,
    val username: String,
    val publicKey: String,
    val createdAt: Long,
    val lastUsedAt: Long? = null,
    val syncId: String? = null
)

@Serializable
@Entity(tableName = "security_events")
data class SecurityEventEntity(
    @PrimaryKey val id: String,
    val eventType: String,
    val domain: String? = null,
    val packageName: String? = null,
    val reason: String? = null,
    val severity: String,
    val timestamp: Long,
    val resolved: Boolean = false
)

@Serializable
@Entity(tableName = "incoming_shares")
data class SharedCredentialEntity(
    @PrimaryKey val id: String,
    val senderUserId: String,
    val encryptedPayload: String,
    val ephemeralSenderPublicKey: String,
    val receivedAt: Long,
    val expiresAt: Long,
    val status: String = "PENDING",
    val decryptedCredentialId: Int? = null
)

@Serializable
@Entity(tableName = "vault_sync_metadata")
data class SyncMetadataEntity(
    @PrimaryKey val userId: String,
    val deviceId: String,
    val lastPushedAt: Long? = null,
    val lastPulledAt: Long? = null,
    val localVersion: Long = 0L,
    val remoteVersion: Long? = null,
    val syncStatus: String = "IDLE",
    val privacyMode: Boolean = false
)

@Serializable
@Entity(tableName = "security_score_history")
data class SecurityScoreHistoryEntity(
    @PrimaryKey val id: String,
    val userId: String,
    val score: Int,
    val grade: String,
    val weakCount: Int = 0,
    val duplicateCount: Int = 0,
    val breachCount: Int = 0,
    val recordedAt: Long
)
