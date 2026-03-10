package com.hariharan.zerokey.security

import kotlinx.serialization.Serializable

/**
 * Represents the encrypted vault blob for Cloud Sync or Backup.
 * This structure follows Zero-Knowledge principles.
 */
@Serializable
data class EncryptedVault(
    val vaultData: String,      // Base64 encrypted JSON of all credentials
    val salt: String,           // Base64 salt used for PBKDF2
    val iv: String,              // Base64 IV for the vault encryption
    val iterations: Int = 600000 // Security parameter
)
