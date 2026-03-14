package com.hariharan.zerokey.sharing

import kotlinx.serialization.Serializable

@Serializable
data class SharedCredential(
    val senderUserId: String,
    val recipientUserId: String,
    val encryptedPayload: String, // AES-GCM encrypted credential data
    val encryptedSessionKey: String, // RSA-OAEP encrypted AES key
    val iv: String,
    val hmac: String,
    val timestamp: Long = System.currentTimeMillis()
)

data class UserPublicKey(
    val userId: String,
    val publicKey: String, // Base64 encoded RSA public key
    val deviceId: String
)
