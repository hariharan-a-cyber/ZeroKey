package com.hariharan.zerokey.core.crypto

import kotlinx.serialization.Serializable

/**
 * Represents the encrypted vault blob for Cloud Sync or Backup.
 * This structure follows Zero-Knowledge principles.
 */
@Serializable
data class EncryptedVault(
    val vaultData: String,      // Base64 encrypted JSON of all credentials
    val salt: String,           // Base64 salt used for KDF
    val iv: String,              // Base64 IV for the vault encryption
    val kdfType: String = "Argon2id", // "PBKDF2" or "Argon2id"
    val iterations: Int = 3,
    val memoryKiB: Int = 65536,  // 64 MB
    val parallelism: Int = 4,
    val integrityHash: String? = null // HMAC-SHA256 for integrity protection
)
