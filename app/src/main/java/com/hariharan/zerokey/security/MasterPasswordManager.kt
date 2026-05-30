package com.hariharan.zerokey.security

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.hariharan.zerokey.utils.SensitiveDataManager
import java.security.SecureRandom
import javax.crypto.spec.SecretKeySpec

/**
 * Manages the vault's master password session, derived key, vault key, and salt storage.
 * Implements Multi-Layer Envelope Encryption:
 * (User Password -> Master Key) wraps (Vault Key)
 * AND (Android Keystore Root Key) wraps the already encrypted Vault Key for hardware binding.
 */
object MasterPasswordManager {

    private const val PREFS_NAME = "master_password_prefs"
    private const val KEY_SALT = "vault_salt"
    private const val KEY_ENCRYPTED_VAULT_KEY = "encrypted_vault_key_blob"
    private const val KEY_VAULT_KEY_IV_INNER = "vault_key_iv_inner"
    private const val KEY_VAULT_KEY_IV_OUTER = "vault_key_iv_outer"
    private const val KEY_AUTH_TIMEOUT = "auth_timeout"
    private const val KEY_CRYPTO_VERSION = "crypto_version"
    private const val KEY_LOCK_ON_EXIT = "lock_on_exit"

    @Volatile
    private var masterKey: SecretKeySpec? = null
    
    @Volatile
    private var vaultKey: SecretKeySpec? = null

    @Volatile
    private var lastUnlockTimestamp: Long = 0
    private const val DEFAULT_AUTOFILL_AUTH_TIMEOUT_MS = 60_000L // 60 seconds

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
        EncryptionManager.init(context)
        val salt = KeyDerivationManager.generateSalt()
        val version = KeyDerivationManager.LATEST_VERSION
        saveSalt(context, salt)
        saveCryptoVersion(context, version)
        
        val derivedMasterKey = KeyDerivationManager.deriveKey(password, salt, version)
        
        // Generate a random 256-bit Vault Key
        val rawVaultKey = ByteArray(32)
        SecureRandom().nextBytes(rawVaultKey)
        val newVaultKey = SecretKeySpec(rawVaultKey, "AES")
        
        // Layer 1: Encrypt with Master Key
        val innerEncrypted = EncryptionManager.encryptWithKey(rawVaultKey, derivedMasterKey)
        
        // Layer 2: Wrap with hardware-backed Root Key
        val outerEncrypted = EncryptionManager.encryptWithRootKey(innerEncrypted.cipherText)
        
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
        EncryptionManager.init(context)
        val salt = getSalt(context) ?: throw IllegalStateException("Vault not set up")
        val version = getCryptoVersion(context)
        val derivedMasterKey = KeyDerivationManager.deriveKey(password, salt, version)
        
        val outerCiphertext = getStoredValue(context, KEY_ENCRYPTED_VAULT_KEY) ?: throw IllegalStateException("Vault key missing")
        val outerIv = getStoredValue(context, KEY_VAULT_KEY_IV_OUTER) ?: throw IllegalStateException("Outer IV missing")
        val innerIv = getStoredValue(context, KEY_VAULT_KEY_IV_INNER) ?: throw IllegalStateException("Inner IV missing")
        
        // Layer 2: Unwrap from hardware-backed Root Key
        val outerEncData = EncryptedData(Base64.decode(outerCiphertext, Base64.NO_WRAP), Base64.decode(outerIv, Base64.NO_WRAP))
        val innerCiphertext = EncryptionManager.decryptWithRootKey(outerEncData)
        
        // Layer 1: Unwrap with Master Key
        val innerEncData = EncryptedData(innerCiphertext, Base64.decode(innerIv, Base64.NO_WRAP))
        val rawVaultKey = EncryptionManager.decryptWithKey(innerEncData, derivedMasterKey)
        
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
     * Wraps the current vault key with the master key for cloud backup/recovery.
     */
    fun getWrappedVaultKey(): EncryptedData? {
        val currentVaultKey = vaultKey ?: return null
        val currentMasterKey = masterKey ?: return null
        return EncryptionManager.encryptWithKey(currentVaultKey.encoded, currentMasterKey)
    }

    /**
     * Imports a vault key from the cloud by unwrapping it with the master key.
     * Then hardens it with the hardware key and saves it locally.
     */
    fun importVaultKey(context: Context, wrappedKey: EncryptedData) {
        val currentMasterKey = masterKey ?: throw IllegalStateException("Vault is locked")
        
        // 1. Unwrap with Master Key
        val rawVaultKey = EncryptionManager.decryptWithKey(wrappedKey, currentMasterKey)
        
        // 2. Wrap with hardware-backed Root Key
        val innerEncrypted = EncryptionManager.encryptWithKey(rawVaultKey, currentMasterKey)
        val outerEncrypted = EncryptionManager.encryptWithRootKey(innerEncrypted.cipherText)
        
        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)
        
        // 3. Update in memory
        vaultKey = SecretKeySpec(rawVaultKey, "AES")
        rawVaultKey.fill(0)
    }

    /**
     * Changes the master password and upgrades crypto parameters if necessary.
     */
    fun changeMasterPassword(context: Context, newPassword: CharArray) {
        val currentVaultKey = vaultKey ?: throw IllegalStateException("Vault must be unlocked")
        
        val newSalt = KeyDerivationManager.generateSalt()
        val newVersion = KeyDerivationManager.LATEST_VERSION
        
        // Derive new master key with latest parameters
        val newMasterKey = KeyDerivationManager.deriveKey(newPassword, newSalt, newVersion)
        
        // Layer 1: Encrypt Vault Key with NEW Master Key
        val rawVaultKey = currentVaultKey.encoded
        val innerEncrypted = EncryptionManager.encryptWithKey(rawVaultKey, newMasterKey)
        
        // Layer 2: Wrap with hardware-backed Root Key
        val outerEncrypted = EncryptionManager.encryptWithRootKey(innerEncrypted.cipherText)
        
        // Persist everything
        saveSalt(context, newSalt)
        saveCryptoVersion(context, newVersion)
        saveHardenedVaultKey(context, innerEncrypted.iv, outerEncrypted)
        
        // Update in-memory keys
        masterKey = newMasterKey
        SensitiveDataManager.clearSensitiveData(rawVaultKey)
    }

    fun lockVault() {
        masterKey?.let { 
            val bytes = it.encoded
            SensitiveDataManager.clearSensitiveData(bytes)
        }
        vaultKey?.let { 
            val bytes = it.encoded
            SensitiveDataManager.clearSensitiveData(bytes)
        }
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
    fun onTrimMemory(level: Int) {
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN) {
            lockVault()
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
        return getPrefs(context).getInt(KEY_CRYPTO_VERSION, 1)
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

    private fun getPrefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )
}
