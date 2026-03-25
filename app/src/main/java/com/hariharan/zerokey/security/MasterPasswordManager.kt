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

    @Volatile
    private var masterKey: SecretKeySpec? = null
    
    @Volatile
    private var vaultKey: SecretKeySpec? = null

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
        saveSalt(context, salt)
        
        val derivedMasterKey = KeyDerivationManager.deriveKey(password, salt)
        
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
        
        SensitiveDataManager.clearSensitiveData(password)
        rawVaultKey.fill(0)
    }

    /**
     * Unlocks the vault by unwrapping the vault key using both hardware key and master password.
     */
    fun unlockVault(context: Context, password: CharArray) {
        EncryptionManager.init(context)
        val salt = getSalt(context) ?: throw IllegalStateException("Vault not set up")
        val derivedMasterKey = KeyDerivationManager.deriveKey(password, salt)
        
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
        
        SensitiveDataManager.clearSensitiveData(password)
        innerCiphertext.fill(0)
        rawVaultKey.fill(0)
    }

    fun getVaultKey(): SecretKeySpec? = vaultKey
    
    fun getSessionKey(): SecretKeySpec? = vaultKey

    fun lockVault() {
        masterKey?.let { SensitiveDataManager.clearSensitiveData(it.encoded) }
        vaultKey?.let { SensitiveDataManager.clearSensitiveData(it.encoded) }
        masterKey = null
        vaultKey = null
    }

    fun isUnlocked(): Boolean = vaultKey != null

    private fun saveSalt(context: Context, salt: ByteArray) {
        getPrefs(context).edit().putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP)).apply()
    }

    fun getSalt(context: Context): ByteArray? {
        val saltString = getPrefs(context).getString(KEY_SALT, null) ?: return null
        return Base64.decode(saltString, Base64.NO_WRAP)
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
