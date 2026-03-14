package com.hariharan.zerokey.emergency

import kotlinx.serialization.Serializable

@Serializable
data class EmergencyConfig(
    val trustedContactUid: String,
    val inactivityDays: Int,
    val encryptedVaultKey: String, // Master key encrypted with contact's public key
    val iv: String,
    val lastActiveTimestamp: Long = System.currentTimeMillis()
)

@Serializable
data class EmergencyRequest(
    val id: String,
    val ownerUid: String,
    val contactUid: String,
    val requestTimestamp: Long = System.currentTimeMillis(),
    val status: RequestStatus = RequestStatus.PENDING
)

enum class RequestStatus { PENDING, CANCELLED, APPROVED }
