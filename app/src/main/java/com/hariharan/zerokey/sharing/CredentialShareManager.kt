package com.hariharan.zerokey.sharing

import android.content.Context
import android.util.Base64
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.hybrid.HybridKeyTemplates
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.firebase.firestore.FirebaseFirestore
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.tasks.await
import java.io.ByteArrayOutputStream
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class CredentialShareManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val firestore: FirebaseFirestore
) {
    init { HybridConfig.register() }

    companion object {
        private const val KEYSET_NAME = "zk_share_keyset"
        private const val MASTER_KEY_URI = "android-keystore://zk_share_master"
        private const val PREF_FILE = "zk_share_prefs"
        private const val COLLECTION_KEYS = "public_keys"
        private const val COLLECTION_SHARES = "shared_credentials"
    }

    private fun getPrivateKeysetHandle(context: Context): KeysetHandle {
        return AndroidKeysetManager.Builder()
            .withSharedPref(context, KEYSET_NAME, PREF_FILE)
            .withKeyTemplate(HybridKeyTemplates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
            .keysetHandle
    }

    suspend fun fetchPublicKey(userId: String): String? {
        return try {
            val snapshot = firestore.collection(COLLECTION_KEYS).document(userId).get().await()
            snapshot.getString("publicKey")
        } catch (e: Exception) { null }
    }

    suspend fun fetchIdentityKey(userId: String): String? {
        return try {
            val snapshot = firestore.collection(COLLECTION_KEYS).document(userId).get().await()
            snapshot.getString("identityPublicKey")
        } catch (e: Exception) { null }
    }

    /** Publishes this user's public keys. Safe to call on every login. */
    suspend fun registerMyKeysIfNeeded(context: Context, userId: String, identityPublicKey: String?) {
        val privateHandle = getPrivateKeysetHandle(context)
        
        // Always update to ensure identity key is present
        val out = ByteArrayOutputStream()
        privateHandle.publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(out))
        val publicKeyB64 = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)

        val data = mutableMapOf(
            "userId" to userId,
            "publicKey" to publicKeyB64
        )
        identityPublicKey?.let { data["identityPublicKey"] = it }

        firestore.collection(COLLECTION_KEYS).document(userId).set(
            data, com.google.firebase.firestore.SetOptions.merge()
        ).await()
    }

    /**
     * Returns a short human-comparable fingerprint of the user's own public key.
     */
    fun getOwnFingerprint(context: Context): String {
        return try {
            val privateHandle = getPrivateKeysetHandle(context)
            val out = ByteArrayOutputStream()
            privateHandle.publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(out))
            val keyBytes = out.toByteArray()
            val digest = java.security.MessageDigest.getInstance("SHA-256").digest(keyBytes)
            digest.copyOfRange(0, 8).joinToString(":") { "%02X".format(it) }
        } catch (e: Exception) {
            "Unknown"
        }
    }

    /**
     * Returns a short human-comparable fingerprint of the recipient's public key
     * (first 8 bytes of SHA-256, colon-separated hex). The sender displays this
     * and the recipient confirms it OUT-OF-BAND before any share is sent. This
     * is what prevents UID-typo / wrong-recipient attacks.
     */
    suspend fun fetchRecipientFingerprint(recipientId: String): String? {
        val pubB64 = fetchPublicKey(recipientId) ?: return null
        val keyBytes = Base64.decode(pubB64, Base64.NO_WRAP)
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(keyBytes)
        return digest.copyOfRange(0, 8).joinToString(":") { "%02X".format(it) }
    }

    /**
     * Shares a credential, encrypting it with Tink HybridEncrypt (ECIES + AES-GCM).
     * The share carries an `expiresAt` so stale shares don't sit in Firestore forever.
     */
    suspend fun shareCredential(senderId: String, recipientId: String, plaintextPayload: String) {
        val recipientPublicKeyB64 = fetchPublicKey(recipientId)
            ?: throw IllegalArgumentException(
                "No ZeroKey user found for that ID. Ask them to open ZeroKey once, then share their ID."
            )

        val publicHandle = KeysetHandle.readNoSecret(
            BinaryKeysetReader.withBytes(Base64.decode(recipientPublicKeyB64, Base64.NO_WRAP))
        )
        val hybridEncrypt = publicHandle.getPrimitive(HybridEncrypt::class.java)
        val contextInfo = "$senderId:$recipientId".toByteArray()
        val encrypted = hybridEncrypt.encrypt(plaintextPayload.toByteArray(), contextInfo)

        val now = System.currentTimeMillis()
        val expiresAt = now + 7L * 24 * 60 * 60 * 1000  // 7 days

        firestore.collection(COLLECTION_SHARES).add(
            mapOf(
                "senderUserId" to senderId,
                "recipientUserId" to recipientId,
                "encryptedPayload" to Base64.encodeToString(encrypted, Base64.NO_WRAP),
                "ephemeralPublicKey" to "",
                "iv" to "",
                "hmac" to "",
                "timestamp" to now,
                "expiresAt" to expiresAt
            )
        ).await()
    }

    suspend fun fetchIncomingShares(userId: String): List<IncomingShare> {
        return try {
            val snapshots = firestore.collection(COLLECTION_SHARES)
                .whereEqualTo("recipientUserId", userId)
                .get().await()
            
            snapshots.documents.map { doc ->
                IncomingShare(
                    id = doc.id,
                    senderUserId = doc.getString("senderUserId") ?: "",
                    encryptedPayload = doc.getString("encryptedPayload") ?: "",
                    timestamp = doc.getLong("timestamp") ?: 0L
                )
            }
        } catch (e: Exception) { emptyList() }
    }

    fun decryptShare(context: Context, share: IncomingShare, userId: String): String {
        val privateHandle = getPrivateKeysetHandle(context)
        val hybridDecrypt = privateHandle.getPrimitive(HybridDecrypt::class.java)
        
        val contextInfo = "${share.senderUserId}:$userId".toByteArray()
        val encrypted = Base64.decode(share.encryptedPayload, Base64.NO_WRAP)
        
        val decrypted = hybridDecrypt.decrypt(encrypted, contextInfo)
        return String(decrypted, Charsets.UTF_8)
    }

    /**
     * Decrypts an Emergency Access vault-key blob.
     *
     * IMPORTANT: this MUST mirror exactly how PasswordViewModel.setupEmergencyAccess
     * encrypted it:
     *   - associated data = "emergency:$ownerUid:$contactUid"
     *   - the plaintext is the RAW vault-key bytes (vaultKey.encoded), NOT base64.
     * Returns the raw vault-key bytes. Caller should zero them after use.
     */
    fun decryptEmergencyVaultKey(
        context: Context,
        encryptedPayloadB64: String,
        ownerUid: String,
        contactUid: String
    ): ByteArray {
        val privateHandle = getPrivateKeysetHandle(context)
        val hybridDecrypt = privateHandle.getPrimitive(HybridDecrypt::class.java)
        val contextInfo = "emergency:$ownerUid:$contactUid".toByteArray()
        val encrypted = Base64.decode(encryptedPayloadB64, Base64.NO_WRAP)
        return hybridDecrypt.decrypt(encrypted, contextInfo)
    }

    suspend fun deleteShare(shareId: String) {
        firestore.collection(COLLECTION_SHARES).document(shareId).delete().await()
    }
}

data class IncomingShare(
    val id: String,
    val senderUserId: String,
    val encryptedPayload: String,
    val timestamp: Long
)
