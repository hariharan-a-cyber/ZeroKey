package com.hariharan.zerokey.data.backup

import android.content.Context
import android.util.Base64
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.sync.VaultSerializer
import com.hariharan.zerokey.security.EncryptedVault
import com.hariharan.zerokey.security.VaultIntegrityManager
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.File
import javax.crypto.SecretKey

/**
 * Handles exporting and importing the entire vault as an encrypted JSON file.
 */
class VaultBackupManager(
    private val repository: PasswordRepository,
    private val serializer: VaultSerializer
) {

    @Serializable
    private data class BackupFile(
        val vault: EncryptedVault,
        val hmac: String,
        val exportTimestamp: Long
    )

    /**
     * Exports the current vault to a file.
     */
    suspend fun exportBackup(file: File, masterKey: SecretKey, hmacKey: SecretKey, salt: String) {
        val entities = repository.getAllEntities()
        
        // 1. Serialize and Encrypt
        val encryptedVault = serializer.serialize(
            entities = entities,
            vaultVersion = System.currentTimeMillis(),
            masterKey = masterKey,
            hmacKey = hmacKey,
            salt = salt
        )

        // 2. Generate HMAC for the backup file integrity
        val hmac = VaultIntegrityManager.sign(encryptedVault.vaultData.toByteArray(), hmacKey)
        
        val backup = BackupFile(
            vault = encryptedVault,
            hmac = Base64.encodeToString(hmac, Base64.NO_WRAP),
            exportTimestamp = System.currentTimeMillis()
        )

        // 3. Write to file
        file.writeText(Json.encodeToString(backup))
    }

    /**
     * Imports a vault from a backup file and merges it into the current database.
     */
    suspend fun importBackup(file: File, masterKey: SecretKey, hmacKey: SecretKey) {
        val json = file.readText()
        val backup = Json.decodeFromString<BackupFile>(json)

        // 1. Verify Integrity
        val hmacBytes = Base64.decode(backup.hmac, Base64.NO_WRAP)
        if (!VaultIntegrityManager.verify(backup.vault.vaultData.toByteArray(), hmacBytes, hmacKey)) {
            throw SecurityException("Backup file integrity verification failed!")
        }

        // 2. Decrypt and Deserialize
        val entities = serializer.deserialize(backup.vault, masterKey)

        // 3. Merge with local database (Latest Modified Wins)
        val localEntities = repository.getAllEntities()
        entities.forEach { imported ->
            val local = localEntities.find { it.id == imported.id }
            if (local == null || imported.lastModified > local.lastModified) {
                repository.syncEntity(imported)
            }
        }
    }
}
