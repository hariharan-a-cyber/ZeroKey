package com.hariharan.zerokey.sharing

import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.tasks.await
import android.util.Base64

/**
 * Registry for discovering user public keys for encrypted sharing.
 */
class PublicKeyRegistry(private val firestore: FirebaseFirestore) {

    private val COLLECTION_KEYS = "public_keys"

    suspend fun registerPublicKey(userId: String, publicKey: java.security.PublicKey, deviceId: String) {
        val keyData = UserPublicKey(
            userId = userId,
            publicKey = Base64.encodeToString(publicKey.encoded, Base64.NO_WRAP),
            deviceId = deviceId
        )
        firestore.collection(COLLECTION_KEYS).document(userId).set(keyData).await()
    }

    suspend fun getPublicKey(userId: String): String? {
        val doc = firestore.collection(COLLECTION_KEYS).document(userId).get().await()
        return doc.getString("publicKey")
    }
}
