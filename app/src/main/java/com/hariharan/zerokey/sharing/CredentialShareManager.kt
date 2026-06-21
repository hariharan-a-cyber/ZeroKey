package com.hariharan.zerokey.sharing

import android.content.Context
import android.util.Base64
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.BinaryKeysetWriter
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

    /** Publishes this user's public key once. Safe to call on every login. */
    suspend fun registerMyKeysIfNeeded(context: Context, userId: String) {
        val privateHandle = getPrivateKeysetHandle(context)
        if (fetchPublicKey(userId) != null) return

        val out = ByteArrayOutputStream()
        privateHandle.publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(out))
        val publicKeyB64 = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)

        firestore.collection(COLLECTION_KEYS).document(userId).set(
            mapOf("userId" to userId, "publicKey" to publicKeyB64)
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
}
