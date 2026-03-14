package com.hariharan.zerokey.sync

import android.util.Log
import com.hariharan.zerokey.security.CryptoEngine
import com.hariharan.zerokey.security.HmacEngine
import kotlinx.serialization.json.Json
import kotlinx.serialization.builtins.ListSerializer
import com.hariharan.zerokey.data.database.PasswordEntity

/**
 * VaultConflictResolver
 *
 * Strategy: Last-Write-Wins based on timestamp.
 * If timestamps are within a 5-second window, merge using field-level union.
 */
class VaultConflictResolver(
    private val cryptoEngine: CryptoEngine,
    private val hmacEngine: HmacEngine
) {
    companion object {
        private const val TAG = "VaultConflictResolver"
        private const val MERGE_WINDOW_MS = 5_000L
    }

    fun resolve(
        remote: EncryptedVaultBlob,
        local: EncryptedVaultBlob?,
        encryptionKey: ByteArray,
        hmacKey: ByteArray
    ): PullResult {
        if (local == null) {
            Log.i(TAG, "No local vault — accepting remote")
            return acceptRemote(remote, encryptionKey, hmacKey)
        }

        val timeDiff = Math.abs(remote.timestamp - local.timestamp)

        return when {
            remote.timestamp > local.timestamp -> {
                Log.i(TAG, "Remote wins (newer by ${remote.timestamp - local.timestamp}ms)")
                acceptRemote(remote, encryptionKey, hmacKey)
            }
            local.timestamp > remote.timestamp -> {
                Log.i(TAG, "Local wins (newer by ${local.timestamp - remote.timestamp}ms)")
                // Return local — caller will re-push
                PullResult.Conflict(resolvedVault = "__LOCAL_WINS__")
            }
            timeDiff <= MERGE_WINDOW_MS -> {
                Log.i(TAG, "Timestamps tied — attempting field-level merge")
                mergeVaults(remote, local, encryptionKey, hmacKey)
            }
            else -> {
                // Exact same timestamp, same version — no real conflict
                acceptRemote(remote, encryptionKey, hmacKey)
            }
        }
    }

    private fun acceptRemote(
        blob: EncryptedVaultBlob,
        encryptionKey: ByteArray,
        hmacKey: ByteArray
    ): PullResult {
        return try {
            val ivBytes = android.util.Base64.decode(blob.iv, android.util.Base64.NO_WRAP)
            val ciphertextBytes = android.util.Base64.decode(blob.encryptedVault, android.util.Base64.NO_WRAP)
            val combined = ivBytes + ciphertextBytes
            
            val decrypted = cryptoEngine.decryptAesGcm(combined, encryptionKey)
            PullResult.Success(String(decrypted, Charsets.UTF_8), blob.vaultVersion)
        } catch (e: Exception) {
            PullResult.Failure("Decryption failed during conflict resolution: ${e.message}")
        }
    }

    /**
     * Field-level merge: union of credential IDs from both vaults.
     * Decrypts both sides, merges JSON at the entity level.
     */
    private fun mergeVaults(
        remote: EncryptedVaultBlob,
        local: EncryptedVaultBlob,
        encryptionKey: ByteArray,
        hmacKey: ByteArray
    ): PullResult {
        return try {
            val remoteIv = android.util.Base64.decode(remote.iv, android.util.Base64.NO_WRAP)
            val remoteCipher = android.util.Base64.decode(remote.encryptedVault, android.util.Base64.NO_WRAP)
            val remoteJson = String(cryptoEngine.decryptAesGcm(remoteIv + remoteCipher, encryptionKey), Charsets.UTF_8)

            val localIv = android.util.Base64.decode(local.iv, android.util.Base64.NO_WRAP)
            val localCipher = android.util.Base64.decode(local.encryptedVault, android.util.Base64.NO_WRAP)
            val localJson = String(cryptoEngine.decryptAesGcm(localIv + localCipher, encryptionKey), Charsets.UTF_8)

            val merged = mergeVaultJson(remoteJson, localJson)
            Log.i(TAG, "Field-level merge succeeded")
            PullResult.Success(merged, maxOf(remote.vaultVersion, local.vaultVersion))
        } catch (e: Exception) {
            Log.e(TAG, "Merge failed, falling back to remote", e)
            acceptRemote(remote, encryptionKey, hmacKey)
        }
    }

    /**
     * JSON-level merge of vault credential arrays.
     * Uses entity.id as the deduplication key.
     */
    private fun mergeVaultJson(remoteJson: String, localJson: String): String {
        val json = Json { ignoreUnknownKeys = true }
        val remoteEntities = json.decodeFromString(ListSerializer(PasswordEntity.serializer()), remoteJson)
        val localEntities = json.decodeFromString(ListSerializer(PasswordEntity.serializer()), localJson)

        val merged = mutableMapOf<Int, PasswordEntity>()

        // Add all local first
        localEntities.forEach { merged[it.id] = it }

        // Remote overwrites only if newer
        remoteEntities.forEach { remote ->
            val existing = merged[remote.id]
            if (existing == null || remote.lastModified > existing.lastModified) {
                merged[remote.id] = remote
            }
        }

        return json.encodeToString(ListSerializer(PasswordEntity.serializer()), merged.values.toList())
    }
}
