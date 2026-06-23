package com.hariharan.zerokey.emergency

import kotlinx.serialization.Serializable

@Serializable
data class EmergencyAccessConfig(
    val ownerUid: String = "",
    val trustedContactUid: String = "",
    val contactEmail: String = "",
    val inactivityDays: Int = 0,
    val encryptedVaultKey: String = "", // Vault Key encrypted with contact's public key
    val iv: String = "",
    val ownerPublicKey: String = "",    // Owner's public key for signature verification
    val contactPublicKey: String = "",  // Contact's public key used for the encryption
    val lastOwnerActivity: Long = System.currentTimeMillis(),
    val setupSignature: String = "",    // Signed by owner: SHA256(ownerUid + trustedContactUid + encryptedVaultKey)
    val status: EmergencyStatus = EmergencyStatus.CONFIGURED
)

@Serializable
data class EmergencyAccessRequest(
    val requestId: String = "",
    val ownerUid: String = "",
    val requesterUid: String = "",
    val requestTimestamp: Long = System.currentTimeMillis(),
    val status: EmergencyStatus = EmergencyStatus.PENDING,
    val approveAt: Long? = null,
    val requesterSignature: String = "" // Signed by contact: SHA256(requestId + ownerUid + requesterUid)
)

enum class EmergencyStatus { CONFIGURED, PENDING, GRANTED, CANCELLED }
