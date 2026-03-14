package com.hariharan.zerokey.sharing

import android.util.Base64
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.security.CryptoEngine
import com.hariharan.zerokey.security.HmacEngine
import kotlinx.coroutines.tasks.await
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

/**
 * Requirement 4: Secure Password Sharing.
 * Implements asymmetric encryption (RSA-OAEP) for credential sharing.
 */
class CredentialShareManager(
    private val firestore: FirebaseFirestore,
    private val cryptoEngine: CryptoEngine,
    private val hmacEngine: HmacEngine
) {

    private val COLLECTION_SHARES = "shared_credentials"
    private val COLLECTION_KEYS = "public_keys"

    /**
     * Shares a credential with another user.
     * 1. Fetches recipient's RSA public key.
     * 2. Generates a random AES session key.
     * 3. Encrypts session key with recipient's public key (RSA-OAEP).
     * 4. Encrypts credential data with session key (AES-GCM).
     * 5. Uploads shared object.
     */
    suspend fun shareCredential(
        senderId: String,
        recipientId: String,
        plaintextPayload: String,
        hmacKey: ByteArray
    ) {
        // 1. Fetch recipient's public key
        val recipientPublicKey = fetchPublicKey(recipientId) ?: throw Exception("Recipient public key not found")

        // 2. Generate random session key (AES-256)
        val sessionKey = java.security.SecureRandom().generateSeed(32)

        // 3. Encrypt session key with RSA-OAEP
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey)
        val encryptedSessionKey = cipher.doFinal(sessionKey)

        // 4. Encrypt payload with AES-GCM
        val encryptedPayloadWithIv = cryptoEngine.encryptAesGcm(plaintextPayload.toByteArray(), sessionKey)
        val iv = encryptedPayloadWithIv.sliceArray(0 until 12)
        val ciphertext = encryptedPayloadWithIv.sliceArray(12 until encryptedPayloadWithIv.size)

        // 5. Sign with HMAC
        val hmac = hmacEngine.computeHmacSha256(ciphertext, hmacKey)

        val share = SharedCredential(
            senderUserId = senderId,
            recipientUserId = recipientId,
            encryptedPayload = Base64.encodeToString(ciphertext, Base64.NO_WRAP),
            encryptedSessionKey = Base64.encodeToString(encryptedSessionKey, Base64.NO_WRAP),
            iv = Base64.encodeToString(iv, Base64.NO_WRAP),
            hmac = Base64.encodeToString(hmac, Base64.NO_WRAP)
        )

        firestore.collection(COLLECTION_SHARES).add(share).await()
    }

    /**
     * Decrypts a shared credential received from another user.
     */
    suspend fun receiveCredential(
        share: SharedCredential,
        myPrivateKey: PrivateKey,
        hmacKey: ByteArray
    ): String {
        // 1. Verify HMAC
        val ciphertext = Base64.decode(share.encryptedPayload, Base64.NO_WRAP)
        val expectedHmac = hmacEngine.computeHmacSha256(ciphertext, hmacKey)
        if (!hmacEngine.constantTimeEquals(Base64.decode(share.hmac, Base64.NO_WRAP), expectedHmac)) {
            throw SecurityException("Shared credential integrity check failed")
        }

        // 2. Decrypt session key with RSA Private Key
        val cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
        cipher.init(Cipher.DECRYPT_MODE, myPrivateKey)
        val sessionKey = cipher.doFinal(Base64.decode(share.encryptedSessionKey, Base64.NO_WRAP))

        // 3. Decrypt payload with session key
        val iv = Base64.decode(share.iv, Base64.NO_WRAP)
        val combined = iv + ciphertext
        val decrypted = cryptoEngine.decryptAesGcm(combined, sessionKey)

        return String(decrypted, Charsets.UTF_8)
    }

    private suspend fun fetchPublicKey(userId: String): PublicKey? {
        val doc = firestore.collection(COLLECTION_KEYS).document(userId).get().await()
        if (!doc.exists()) return null
        
        val keyBase64 = doc.getString("publicKey") ?: return null
        val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
        return KeyFactory.getInstance("RSA").generatePublic(X509EncodedKeySpec(keyBytes))
    }

    /**
     * Generates and registers a new RSA key pair for the user.
     */
    suspend fun registerMyKeys(userId: String, deviceId: String): java.security.KeyPair {
        val kpg = KeyPairGenerator.getInstance("RSA")
        kpg.initialize(2048)
        val pair = kpg.generateKeyPair()

        val keyData = mapOf(
            "userId" to userId,
            "publicKey" to Base64.encodeToString(pair.public.encoded, Base64.NO_WRAP),
            "deviceId" to deviceId
        )

        firestore.collection(COLLECTION_KEYS).document(userId).set(keyData).await()
        return pair
    }
}
