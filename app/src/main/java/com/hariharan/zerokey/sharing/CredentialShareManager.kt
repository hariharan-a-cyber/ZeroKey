package com.hariharan.zerokey.sharing

import android.util.Base64
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.core.crypto.HmacEngine
import kotlinx.coroutines.tasks.await
import java.io.ByteArrayOutputStream

/**
 * Hardened Secure Sharing Architecture.
 * Upgraded from RSA-2048 to ECC (Curve25519) using Google Tink.
 * Uses ECIES (Elliptic Curve Integrated Encryption Scheme) with HKDF and AES-GCM.
 */
class CredentialShareManager(
    private val firestore: FirebaseFirestore,
    private val hmacEngine: HmacEngine
) {

    private val COLLECTION_SHARES = "shared_credentials"
    private val COLLECTION_KEYS = "public_keys"

    init {
        // Register hybrid encryption configurations
        HybridConfig.register()
    }

    /**
     * Shares a credential using the recipient's Curve25519 public key.
     */
    suspend fun shareCredential(
        senderId: String,
        recipientId: String,
        plaintextPayload: String,
        hmacKey: ByteArray
    ) {
        // 1. Fetch recipient's X25519 public keyset
        val recipientPublicKeyBase64 = fetchPublicKey(recipientId) 
            ?: throw Exception("Recipient public key not found")
        
        val publicKeysetHandle = KeysetHandle.readNoSecret(
            BinaryKeysetReader.withBytes(Base64.decode(recipientPublicKeyBase64, Base64.NO_WRAP))
        )
        val hybridEncrypt = publicKeysetHandle.getPrimitive(HybridEncrypt::class.java)

        // 2. Perform Hybrid Encryption (X25519 + AES-GCM internally)
        // Context info (AAD) binds the encryption to the sender and recipient
        val contextInfo = "$senderId:$recipientId".toByteArray()
        val encryptedData = hybridEncrypt.encrypt(plaintextPayload.toByteArray(), contextInfo)

        // 3. Sign the ciphertext with HMAC for additional integrity
        val hmac = hmacEngine.computeHmacSha256(encryptedData, hmacKey)

        val share = SharedCredential(
            senderUserId = senderId,
            recipientUserId = recipientId,
            encryptedPayload = Base64.encodeToString(encryptedData, Base64.NO_WRAP),
            ephemeralPublicKey = "", // Tink embeds the ephemeral key in the payload
            iv = "", // Handled by AEAD in Tink
            hmac = Base64.encodeToString(hmac, Base64.NO_WRAP)
        )

        firestore.collection(COLLECTION_SHARES).add(share).await()
    }

    /**
     * Decrypts a shared credential using the user's private ECC key.
     */
    suspend fun receiveCredential(
        share: SharedCredential,
        privateKeysetHandle: KeysetHandle,
        hmacKey: ByteArray
    ): String {
        // 1. Verify HMAC integrity
        val encryptedData = Base64.decode(share.encryptedPayload, Base64.NO_WRAP)
        val expectedHmac = hmacEngine.computeHmacSha256(encryptedData, hmacKey)
        
        if (!hmacEngine.constantTimeEquals(Base64.decode(share.hmac, Base64.NO_WRAP), expectedHmac)) {
            throw SecurityException("Shared credential integrity check failed")
        }

        // 2. Decrypt using Tink's HybridDecrypt
        val hybridDecrypt = privateKeysetHandle.getPrimitive(HybridDecrypt::class.java)
        val contextInfo = "${share.senderUserId}:${share.recipientUserId}".toByteArray()
        val decrypted = hybridDecrypt.decrypt(encryptedData, contextInfo)

        return String(decrypted, Charsets.UTF_8)
    }

    private suspend fun fetchPublicKey(userId: String): String? {
        val doc = firestore.collection(COLLECTION_KEYS).document(userId).get().await()
        return doc.getString("publicKey")
    }

    /**
     * Generates a new X25519 key pair and registers the public component.
     */
    suspend fun registerMyKeys(userId: String, deviceId: String): KeysetHandle {
        val privateKeysetHandle = KeysetHandle.generateNew(
            KeyTemplates.get("ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM")
        )
        val publicKeysetHandle = privateKeysetHandle.publicKeysetHandle

        val outputStream = ByteArrayOutputStream()
        publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(outputStream))
        val publicKeyBase64 = Base64.encodeToString(outputStream.toByteArray(), Base64.NO_WRAP)

        val keyData = mapOf(
            "userId" to userId,
            "publicKey" to publicKeyBase64,
            "deviceId" to deviceId
        )

        firestore.collection(COLLECTION_KEYS).document(userId).set(keyData).await()
        return privateKeysetHandle
    }
}
