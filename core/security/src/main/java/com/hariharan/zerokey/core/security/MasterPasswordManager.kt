package com.hariharan.zerokey.core.security

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import com.hariharan.zerokey.core.common.SensitiveDataManager
import com.hariharan.zerokey.core.crypto.EncryptedData
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.crypto.KeyDerivationManager
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Manages the vault's master password session, derived key, vault key, and salt storage.
 * Implements Multi-Layer Envelope Encryption:
 * (User Password -> Master Key) wraps (Vault Key)
 * AND (Android Keystore Root Key) wraps the already encrypted Vault Key for hardware binding.
 */
@Singleton
class MasterPasswordManager @Inject constructor(
    private val encryptionManager: EncryptionManager,
    private val keyDerivationManager: KeyDerivationManager
) {

    companion object {
        private const val PREFS_NAME = "master_password_prefs"
        private const val KEY_SALT = "vault_salt"
        private const val KEY_ENCRYPTED_VAULT_KEY = "encrypted_vault_key_blob"
        private const val KEY_VAULT_KEY_IV_INNER = "vault_key_iv_inner"
        private const val KEY_VAULT_KEY_IV_OUTER = "vault_key_iv_outer"
        private const val KEY_AUTH_TIMEOUT = "auth_timeout"
        private const val KEY_CRYPTO_VERSION = "crypto_version"
        private const val KEY_LOCK_ON_EXIT = "lock_on_exit"
        private const val KEY_RECOVERY_BLOB = "recovery_wrapped_vault_key"
        private const val KEY_RECOVERY_IV = "recovery_iv"
        private const val DEFAULT_AUTOFILL_AUTH_TIMEOUT_MS = 60_000L // 60 seconds
    }

    @Volatile
    private var masterKey: SecretKeySpec? = null
    
    @Volatile
    private var vaultKey: SecretKeySpec? = null

    @Volatile
    private var lastUnlockTimestamp: Long = 0

    @Volatile
    private var cachedPrefs: android.content.SharedPreferences? = null

    /**
     * Checks if a master password and vault key have already been set up.
     */
    fun isSetup(context: Context): Boolean {
        return getSalt(context) != null && getStoredValue(context, KEY_ENCRYPTED_VAULT_KEY) != null
    }

    /**
     * Setup the vault for the first time.
     * Generates a random 256-bit Vault Key.
     * Layer 1: Encrypt Vault Key with Master Key (password-derived).
     * Layer 2: Encrypt result with Android Keystore Root Key (hardware-backed).
     */
    fun setupVault(context: Context, password: CharArray) {
        encryptionManager.init()
        val salt = keyDerivationManager.generateSalt()
        val version = KeyDerivationManager.LATEST_VERSION
        saveSalt(context, salt)
        saveCryptoVersion(context, version)
        
        val derivedMasterKey = keyDerivationManager.deriveKey(password, salt, version)
        
        // Generate a random 256-bit Vault Key
        val rawVaultKey = ByteArray(32)
        SecureRandom().nextBytes(rawVaultKey)
        val newVaultKey = SecretKeySpec(rawVaultKey, "AES")
        
        // Layer 1: Encrypt with Master Key
        val innerEncrypted = encryptionManager.encryptWithKey(rawVaultKey, derivedMasterKey)
        
        // Layer 2: Wrap with hardware-backed Root Key
        val outerEncrypted = encryptionManager.encryptWithRootKey(innerEncrypted.cipherText)
        
        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)
        
        // Store in memory for immediate use
        masterKey = derivedMasterKey
        vaultKey = newVaultKey
        lastUnlockTimestamp = System.currentTimeMillis()
        
        SensitiveDataManager.clearSensitiveData(password)
        rawVaultKey.fill(0)
    }

    /**
     * Unlocks the vault by unwrapping the vault key using both hardware key and master password.
     */
    fun unlockVault(context: Context, password: CharArray) {
        encryptionManager.init()
        val salt = getSalt(context) ?: throw IllegalStateException("Vault not set up")
        val version = getCryptoVersion(context)
        val derivedMasterKey = keyDerivationManager.deriveKey(password, salt, version)
        
        val outerCiphertext = getStoredValue(context, KEY_ENCRYPTED_VAULT_KEY) ?: throw IllegalStateException("Vault key missing")
        val outerIv = getStoredValue(context, KEY_VAULT_KEY_IV_OUTER) ?: throw IllegalStateException("Outer IV missing")
        val innerIv = getStoredValue(context, KEY_VAULT_KEY_IV_INNER) ?: throw IllegalStateException("Inner IV missing")
        
        // Layer 2: Unwrap from hardware-backed Root Key
        val outerEncData = EncryptedData(Base64.decode(outerCiphertext, Base64.NO_WRAP), Base64.decode(outerIv, Base64.NO_WRAP))
        val innerCiphertext = encryptionManager.decryptWithRootKey(outerEncData)
        
        // Layer 1: Unwrap with Master Key
        val innerEncData = EncryptedData(innerCiphertext, Base64.decode(innerIv, Base64.NO_WRAP))
        val rawVaultKey = encryptionManager.decryptWithKey(innerEncData, derivedMasterKey)
        
        masterKey = derivedMasterKey
        vaultKey = SecretKeySpec(rawVaultKey, "AES")
        lastUnlockTimestamp = System.currentTimeMillis()
        
        SensitiveDataManager.clearSensitiveData(password)
        innerCiphertext.fill(0)
        rawVaultKey.fill(0)
    }

    fun getVaultKey(): SecretKeySpec? = vaultKey
    
    fun getSessionKey(): SecretKeySpec? = vaultKey

    /**
     * Sets the vault key in memory ONLY (no persistence), e.g. after a biometric unlock.
     * The hardened on-disk wrapped vault key is unchanged.
     */
    fun restoreVaultKey(rawVaultKey: ByteArray) {
        vaultKey = SecretKeySpec(rawVaultKey, "AES")
        lastUnlockTimestamp = System.currentTimeMillis()
    }

    /**
     * Wraps the current vault key with the master key for cloud backup/recovery.
     */
    fun getWrappedVaultKey(): EncryptedData? {
        val currentVaultKey = vaultKey ?: return null
        val currentMasterKey = masterKey ?: return null
        return encryptionManager.encryptWithKey(currentVaultKey.encoded, currentMasterKey)
    }

    /**
     * Installs a brand-new raw vault key, re-wrapping it under the current master key
     * and the hardware root key. Used by key rotation. Vault must be unlocked.
     */
    fun installNewVaultKey(context: Context, rawVaultKey: ByteArray) {
        val currentMasterKey = masterKey ?: throw IllegalStateException("Vault is locked")

        // Layer 1: Encrypt new vault key with the current Master Key
        val innerEncrypted = encryptionManager.encryptWithKey(rawVaultKey, currentMasterKey)
        // Layer 2: Wrap with hardware-backed Root Key
        val outerEncrypted = encryptionManager.encryptWithRootKey(innerEncrypted.cipherText)

        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)

        // Update in-memory vault key
        vaultKey = SecretKeySpec(rawVaultKey, "AES")
    }

    /**
     * Imports a vault key from the cloud by unwrapping it with the master key.
     * Then hardens it with the hardware key and saves it locally.
     */
    fun importVaultKey(context: Context, wrappedKey: EncryptedData) {
        val currentMasterKey = masterKey ?: throw IllegalStateException("Vault is locked")
        
        // 1. Unwrap with Master Key
        val rawVaultKey = encryptionManager.decryptWithKey(wrappedKey, currentMasterKey)
        
        // 2. Wrap with hardware-backed Root Key
        val innerEncrypted = encryptionManager.encryptWithKey(rawVaultKey, currentMasterKey)
        val outerEncrypted = encryptionManager.encryptWithRootKey(innerEncrypted.cipherText)
        
        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)
        
        // 3. Update in memory
        vaultKey = SecretKeySpec(rawVaultKey, "AES")
        rawVaultKey.fill(0)
    }

    // ---------- Recovery key (forgot-password reset without data loss) ----------

    data class RecoveryBlob(val blobB64: String, val ivB64: String)

    data class RecoveryMaterial(
        val recoveryCode: String,
        val blobs: List<RecoveryBlob>
    )

    /**
     * Creates 5 independent recovery codes (32 chars each) and wraps the CURRENT vault key with them. 
     * Vault must be unlocked. Caller stores blobs (cloud + local) and shows codes once.
     */
    fun createRecoveryMaterial(): RecoveryMaterial {
        val vk = vaultKey ?: throw IllegalStateException("Vault must be unlocked")
        val rawVaultKey = vk.encoded
        val codes = mutableListOf<String>()
        val blobs = mutableListOf<RecoveryBlob>()

        repeat(5) {
            val recBytes = ByteArray(16) // 128 bits = 32 hex chars
            SecureRandom().nextBytes(recBytes)
            val code = recBytes.joinToString("") { "%02X".format(it) }
            val wrapped = encryptionManager.encryptWithKey(rawVaultKey, SecretKeySpec(recBytes, "AES"))
            
            codes.add(code)
            blobs.add(RecoveryBlob(
                Base64.encodeToString(wrapped.cipherText, Base64.NO_WRAP),
                Base64.encodeToString(wrapped.iv, Base64.NO_WRAP)
            ))
        }
        
        SensitiveDataManager.clearSensitiveData(rawVaultKey)
        return RecoveryMaterial(codes.joinToString("-"), blobs)
    }

    /**
     * Recovers the vault using ONE of the recovery codes + the stored wrapped blobs.
     * Trial-and-error decryption against all 5 blobs. Success on GCM tag match.
     */
    fun recoverWithRecoveryCode(
        context: Context,
        blobs: List<RecoveryBlob>,
        recoveryCode: String,
        newPassword: CharArray
    ) {
        encryptionManager.init()
        val recBytes = parseRecoveryCode(recoveryCode)
        val recoveryKeySpec = SecretKeySpec(recBytes, "AES")
        
        var rawVaultKey: ByteArray? = null
        var lastError: Exception? = null

        // Attempt to decrypt with EACH blob until one works (Zero-knowledge trial)
        for (blob in blobs) {
            try {
                val wrapped = EncryptedData(
                    Base64.decode(blob.blobB64, Base64.NO_WRAP),
                    Base64.decode(blob.ivB64, Base64.NO_WRAP)
                )
                rawVaultKey = encryptionManager.decryptWithKey(wrapped, recoveryKeySpec)
                if (rawVaultKey != null) break 
            } catch (e: Exception) {
                lastError = e
            }
        }

        if (rawVaultKey == null) {
            recBytes.fill(0)
            throw lastError ?: Exception("Invalid recovery key")
        }
        recBytes.fill(0)

        val newSalt = keyDerivationManager.generateSalt()
        val newVersion = KeyDerivationManager.LATEST_VERSION
        val newMasterKey = keyDerivationManager.deriveKey(newPassword, newSalt, newVersion)
        val innerEncrypted = encryptionManager.encryptWithKey(rawVaultKey, newMasterKey)
        val outerEncrypted = encryptionManager.encryptWithRootKey(innerEncrypted.cipherText)

        saveSalt(context, newSalt)
        saveCryptoVersion(context, newVersion)
        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)

        masterKey = newMasterKey
        vaultKey = SecretKeySpec(rawVaultKey, "AES")
        lastUnlockTimestamp = System.currentTimeMillis()

        SensitiveDataManager.clearSensitiveData(newPassword)
        rawVaultKey.fill(0)
    }

    fun saveRecoveryBlobLocal(context: Context, blobs: List<RecoveryBlob>) {
        val combined = blobs.joinToString(";") { "${it.blobB64}|${it.ivB64}" }
        getPrefs(context).edit()
            .putString(KEY_RECOVERY_BLOB, combined)
            .apply()
    }

    fun getLocalRecoveryBlobs(context: Context): List<RecoveryBlob> {
        val combined = getStoredValue(context, KEY_RECOVERY_BLOB) ?: return emptyList()
        return try {
            combined.split(";").map {
                val parts = it.split("|")
                RecoveryBlob(parts[0], parts[1])
            }
        } catch (e: Exception) { emptyList() }
    }

    fun clearRecoveryBlobLocal(context: Context) {
        getPrefs(context).edit().remove(KEY_RECOVERY_BLOB).remove(KEY_RECOVERY_IV).apply()
    }

    private fun formatRecoveryCode(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }.chunked(4).joinToString("-")

    private fun parseRecoveryCode(code: String): ByteArray {
        val hex = code.filter { it.isLetterOrDigit() }.uppercase()
        val byteLen = hex.length / 2
        return ByteArray(byteLen) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }

    /**
     * Changes the master password and upgrades crypto parameters if necessary.
     */
    fun changeMasterPassword(context: Context, newPassword: CharArray) {
        val currentVaultKey = vaultKey ?: throw IllegalStateException("Vault must be unlocked")
        
        val newSalt = keyDerivationManager.generateSalt()
        val newVersion = KeyDerivationManager.LATEST_VERSION
        
        // Derive new master key with latest parameters
        val newMasterKey = keyDerivationManager.deriveKey(newPassword, newSalt, newVersion)
        
        // Layer 1: Encrypt Vault Key with NEW Master Key
        val rawVaultKey = currentVaultKey.encoded
        val innerEncrypted = encryptionManager.encryptWithKey(rawVaultKey, newMasterKey)
        
        // Layer 2: Wrap with hardware-backed Root Key
        val outerEncrypted = encryptionManager.encryptWithRootKey(innerEncrypted.cipherText)
        
        // Persist everything
        saveSalt(context, newSalt)
        saveCryptoVersion(context, newVersion)
        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)
        
        // Update in-memory keys
        masterKey = newMasterKey
        SensitiveDataManager.clearSensitiveData(rawVaultKey)
    }

    fun lockVault() {
        // Note: SecretKeySpec.getEncoded() returns a COPY, so it cannot be wiped in place.
        // Dropping the references and letting GC reclaim them is the real protection.
        masterKey = null
        vaultKey = null
        lastUnlockTimestamp = 0
    }

    fun isUnlocked(): Boolean = vaultKey != null

    /**
     * Checks if the vault is unlocked AND the recent authentication is still valid.
     */
    fun isAutofillAuthorized(context: android.content.Context): Boolean {
        if (vaultKey == null) return false
        val now = System.currentTimeMillis()
        val timeout = getAuthTimeout(context)
        if (timeout == 0L) return false // Always require biometric
        return (now - lastUnlockTimestamp) < timeout
    }

    fun getAuthTimeout(context: android.content.Context): Long {
        return getPrefs(context).getLong(KEY_AUTH_TIMEOUT, DEFAULT_AUTOFILL_AUTH_TIMEOUT_MS)
    }

    fun setAuthTimeout(context: android.content.Context, timeoutMs: Long) {
        getPrefs(context).edit().putLong(KEY_AUTH_TIMEOUT, timeoutMs).apply()
    }

    fun shouldLockOnExit(context: Context): Boolean {
        return getPrefs(context).getBoolean(KEY_LOCK_ON_EXIT, true)
    }

    fun setLockOnExit(context: Context, enabled: Boolean) {
        getPrefs(context).edit().putBoolean(KEY_LOCK_ON_EXIT, enabled).apply()
    }

    /**
     * Resets the autofill authorization timer (e.g. after a fresh biometric check).
     */
    fun authorizeAutofill() {
        lastUnlockTimestamp = System.currentTimeMillis()
    }

    /**
     * Responds to system memory pressure by purging sensitive keys.
     */
    fun onTrimMemory(level: Int, context: Context? = null) {
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            // Only wipe keys if the user's policy says to lock on exit.
            // If context is null (legacy call), default to locking for safety.
            if (context == null || shouldLockOnExit(context)) {
                lockVault()
            }
        }
    }

    private fun saveSalt(context: Context, salt: ByteArray) {
        getPrefs(context).edit().putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP)).apply()
    }

    fun getSalt(context: Context): ByteArray? {
        val saltString = getPrefs(context).getString(KEY_SALT, null) ?: return null
        return Base64.decode(saltString, Base64.NO_WRAP)
    }

    private fun saveCryptoVersion(context: Context, version: Int) {
        getPrefs(context).edit().putInt(KEY_CRYPTO_VERSION, version).apply()
    }

    fun getCryptoVersion(context: Context): Int {
        return getPrefs(context).getInt(KEY_CRYPTO_VERSION, KeyDerivationManager.LATEST_VERSION)
    }

    private fun saveHardenedVaultKey(context: Context, innerIv: ByteArray, outerEnc: EncryptedData) {
        getPrefs(context).edit().apply {
            putString(KEY_ENCRYPTED_VAULT_KEY, Base64.encodeToString(outerEnc.cipherText, Base64.NO_WRAP))
            putString(KEY_VAULT_KEY_IV_OUTER, Base64.encodeToString(outerEnc.iv, Base64.NO_WRAP))
            putString(KEY_VAULT_KEY_IV_INNER, Base64.encodeToString(innerIv, Base64.NO_WRAP))
            apply()
        }
    }

    private fun getStoredValue(context: Context, key: String): String? = getPrefs(context).getString(key, null)

    private fun getPrefs(context: Context): android.content.SharedPreferences {
        cachedPrefs?.let { return it }
        val appContext = context.applicationContext
        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)
        val prefs = EncryptedSharedPreferences.create(
            PREFS_NAME,
            masterKeyAlias,
            appContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
        cachedPrefs = prefs
        return prefs
    }
}
