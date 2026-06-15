package com.hariharan.zerokey.sharing

import android.content.Context
import android.util.Base64
import com.google.crypto.tink.HybridDecrypt
import com.google.crypto.tink.HybridEncrypt
import com.google.crypto.tink.KeyTemplates
import com.google.crypto.tink.KeysetHandle
import com.google.crypto.tink.BinaryKeysetWriter
import com.google.crypto.tink.BinaryKeysetReader
import com.google.crypto.tink.hybrid.HybridConfig
import com.google.crypto.tink.integration.android.AndroidKeysetManager
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.core.crypto.HmacEngine
import kotlinx.coroutines.tasks.await
import java.io.ByteArrayOutputStream

/**
 * Zero-knowledge credential sharing using Tink ECIES (X25519/P-256 + HKDF + AES-GCM).
 * The private keyset is persisted on-device, encrypted by an Android Keystore master key.
 * Integrity is provided by Tink's AEAD with sender:recipient bound as AAD.
 */
class CredentialShareManager(
    private val firestore: FirebaseFirestore,
    private val hmacEngine: HmacEngine
) {
    private val COLLECTION_SHARES = "shared_credentials"
    private val COLLECTION_KEYS = "public_keys"

    companion object {
        private const val KEYSET_PREF = "zerokey_share_keyset_prefs"
        private const val KEYSET_NAME = "zerokey_share_keyset"
        private const val MASTER_KEY_URI = "android-keystore://zerokey_share_master"
        private const val KEY_TEMPLATE = "ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM"
    }

    init { HybridConfig.register() }

    /** Loads (or creates) this device's persistent private keyset (Keystore-encrypted at rest). */
    private fun getPrivateKeysetHandle(context: Context): KeysetHandle {
        return AndroidKeysetManager.Builder()
            .withSharedPref(context.applicationContext, KEYSET_NAME, KEYSET_PREF)
            .withKeyTemplate(KeyTemplates.get(KEY_TEMPLATE))
            .withMasterKeyUri(MASTER_KEY_URI)
            .build()
            .keysetHandle
    }

    /** Publishes this user's public key once. Safe to call on every login. */
    suspend fun registerMyKeysIfNeeded(context: Context, userId: String) {
        val privateHandle = getPrivateKeysetHandle(context) // creates locally if missing
        if (fetchPublicKey(userId) != null) return          // already published

        val out = ByteArrayOutputStream()
        privateHandle.publicKeysetHandle.writeNoSecret(BinaryKeysetWriter.withOutputStream(out))
        val publicKeyB64 = Base64.encodeToString(out.toByteArray(), Base64.NO_WRAP)

        firestore.collection(COLLECTION_KEYS).document(userId).set(
            mapOf("userId" to userId, "publicKey" to publicKeyB64)
        ).await()
    }

    /** Shares a credential. Throws a clear error if the recipient ID has no published key. */
    suspend fun shareCredential(senderId: String, recipientId: String, plaintextPayload: String) {
        val recipientPublicKeyB64 = fetchPublicKey(recipientId)
            ?: throw IllegalArgumentException("No ZeroKey user found for that ID. Ask them to open ZeroKey once, then share their ID.")

        val publicHandle = KeysetHandle.readNoSecret(
            BinaryKeysetReader.withBytes(Base64.decode(recipientPublicKeyB64, Base64.NO_WRAP))
        )
        val hybridEncrypt = publicHandle.getPrimitive(HybridEncrypt::class.java)
        val contextInfo = "$senderId:$recipientId".toByteArray()
        val encrypted = hybridEncrypt.encrypt(plaintextPayload.toByteArray(), contextInfo)

        val share = SharedCredential(
            senderUserId = senderId,
            recipientUserId = recipientId,
            encryptedPayload = Base64.encodeToString(encrypted, Base64.NO_WRAP),
            ephemeralPublicKey = "",
            iv = "",
            hmac = "" // Integrity provided by Tink AEAD; no separate HMAC needed.
        )
        firestore.collection(COLLECTION_SHARES).add(share).await()
    }

    /** Decrypts a received share using this device's private keyset. */
    suspend fun receiveCredential(context: Context, share: SharedCredential): String {
        val privateHandle = getPrivateKeysetHandle(context)
        val hybridDecrypt = privateHandle.getPrimitive(HybridDecrypt::class.java)
        val contextInfo = "${share.senderUserId}:${share.recipientUserId}".toByteArray()
        val encrypted = Base64.decode(share.encryptedPayload, Base64.NO_WRAP)
        return String(hybridDecrypt.decrypt(encrypted, contextInfo), Charsets.UTF_8)
    }

    private suspend fun fetchPublicKey(userId: String): String? {
        val doc = firestore.collection(COLLECTION_KEYS).document(userId).get().await()
        return doc.getString("publicKey")
    }
}
