package com.hariharan.zerokey.sync

data class EncryptedVaultBlob(
    val deviceId: String,
    val vaultVersion: Long,
    val encryptedVault: String,   // Base64(AES-256-GCM ciphertext + IV + tag)
    val iv: String,               // Added IV field for compatibility with existing architecture
    val hmac: String,             // Base64(HMAC-SHA256)
    val timestamp: Long,
    val wrappedVaultKey: String? = null,
    val wrappedVaultKeyIv: String? = null,
    val vaultEpochId: String = "",
    val previousSnapshotHmac: String? = null
) {
    fun toMap(): Map<String, Any?> = mapOf(
        "deviceId" to deviceId,
        "vaultVersion" to vaultVersion,
        "encryptedVault" to encryptedVault,
        "iv" to iv,
        "hmac" to hmac,
        "timestamp" to timestamp,
        "wrappedVaultKey" to wrappedVaultKey,
        "wrappedVaultKeyIv" to wrappedVaultKeyIv,
        "vaultEpochId" to vaultEpochId,
        "previousSnapshotHmac" to previousSnapshotHmac
    )

    companion object {
        fun fromMap(map: Map<String, Any>): EncryptedVaultBlob = EncryptedVaultBlob(
            deviceId = map["deviceId"] as String,
            vaultVersion = (map["vaultVersion"] as Long),
            encryptedVault = map["encryptedVault"] as String,
            iv = map["iv"] as? String ?: "",
            hmac = map["hmac"] as String,
            timestamp = map["timestamp"] as Long,
            wrappedVaultKey = map["wrappedVaultKey"] as? String,
            wrappedVaultKeyIv = map["wrappedVaultKeyIv"] as? String,
            vaultEpochId = map["vaultEpochId"] as? String ?: "",
            previousSnapshotHmac = map["previousSnapshotHmac"] as? String
        )
    }
}

sealed class SyncResult {
    data class Success(val version: Long, val snapshotHmac: String) : SyncResult()
    data class Failure(val reason: String) : SyncResult()
}

sealed class PullResult {
    data class Success(val plaintextVault: String, val version: Long, val snapshotHmac: String, val epochId: String = "") : PullResult()
    object NoRemoteVault : PullResult()
    data class Conflict(val resolvedVault: String) : PullResult()
    data class IntegrityFailure(val reason: String, val blob: EncryptedVaultBlob? = null) : PullResult()
    data class Failure(val reason: String) : PullResult()
}

sealed class SyncEvent {
    data class RemoteUpdate(val version: Long) : SyncEvent()
    object NoChange : SyncEvent()
}
