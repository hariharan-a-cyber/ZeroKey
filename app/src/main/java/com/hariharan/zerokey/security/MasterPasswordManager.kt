package com.hariharan.zerokey.security

import android.content.Context
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import com.hariharan.zerokey.utils.SensitiveDataManager
import javax.crypto.spec.SecretKeySpec

/**
 * Manages the vault's master password session, derived key, and salt storage.
 */
object MasterPasswordManager {

    private const val PREFS_NAME = "master_password_prefs"
    private const val KEY_SALT = "vault_salt"

    @Volatile
    private var sessionKey: SecretKeySpec? = null

    /**
     * Checks if a master password has already been set up.
     */
    fun isSetup(context: Context): Boolean {
        return getSalt(context) != null
    }

    /**
     * Saves the salt securely during setup.
     */
    fun saveSalt(context: Context, salt: ByteArray) {
        val prefs = getPrefs(context)
        prefs.edit().putString(KEY_SALT, Base64.encodeToString(salt, Base64.NO_WRAP)).apply()
    }

    /**
     * Retrieves the stored salt.
     */
    fun getSalt(context: Context): ByteArray? {
        val prefs = getPrefs(context)
        val saltString = prefs.getString(KEY_SALT, null) ?: return null
        return Base64.decode(saltString, Base64.NO_WRAP)
    }

    private fun getPrefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_NAME,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    /**
     * Unlocks the vault by deriving the key and storing it in memory.
     */
    fun unlockVault(password: CharArray, salt: ByteArray) {
        val key = KeyDerivationManager.deriveKey(password, salt)
        sessionKey = key
        SensitiveDataManager.clearSensitiveData(password)
    }

    /**
     * Returns the session key if the vault is unlocked.
     */
    fun getSessionKey(): SecretKeySpec? = sessionKey

    /**
     * Locks the vault and wipes the session key from memory.
     */
    fun lockVault() {
        sessionKey?.let {
            SensitiveDataManager.clearSensitiveData(it.encoded)
        }
        sessionKey = null
    }

    /**
     * Checks if the vault is currently unlocked in this session.
     */
    fun isUnlocked(): Boolean = sessionKey != null
}
