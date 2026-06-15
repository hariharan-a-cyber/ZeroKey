package com.hariharan.zerokey.security

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.hariharan.zerokey.core.common.PrivacyLogger
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Optional convenience layer: lets a TRUSTED device unlock the vault with biometrics,
 * without weakening zero-knowledge.
 *
 * The vault key is wrapped by a SEPARATE hardware Keystore key that:
 *  - requires biometric auth on every use (CryptoObject-bound),
 *  - is invalidated automatically if the user's enrolled biometrics change.
 * The master password remains the root of trust and the recovery path. This only stores
 * a hardware-encrypted copy of the vault key on THIS device.
 */
class BiometricVaultUnlockManager(context: Context) {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences =
        appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "zerokey_biometric_unlock"
        private const val KEY_BLOB = "bio_wrapped_vault_key"
        private const val KEY_IV = "bio_iv"
        private const val BIO_KEY_ALIAS = "ZeroKeyBiometricKey"
        private const val AES_MODE = "AES/GCM/NoPadding"
        private const val TAG_LENGTH = 128
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }

    /** True if this device has usable enrolled biometrics. */
    fun isBiometricAvailable(): Boolean =
        BiometricManager.from(appContext)
            .canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_STRONG) ==
                BiometricManager.BIOMETRIC_SUCCESS

    /**
     * Whether biometric unlock should be OFFERED at all. Restricted to API 30+ because the
     * per-use CryptoObject binding on API 26-29 has OEM quirks; below 30 we use master password.
     */
    fun isSupported(): Boolean = Build.VERSION.SDK_INT >= 30 && isBiometricAvailable()

    /** True if the user has enabled biometric unlock (a wrapped key blob exists). */
    fun isEnrolled(): Boolean = prefs.contains(KEY_BLOB) && prefs.contains(KEY_IV)

    /** Removes biometric unlock (on disable / sign-out / key rotation / invalidation). */
    fun clear() {
        prefs.edit().remove(KEY_BLOB).remove(KEY_IV).apply()
        try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }.deleteEntry(BIO_KEY_ALIAS)
        } catch (_: Exception) {}
    }

    private fun buildKey(useStrongBox: Boolean): SecretKey {
        val kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val builder = KeyGenParameterSpec.Builder(
            BIO_KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= 30) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(useStrongBox)
        }
        kg.init(builder.build())
        return kg.generateKey()
    }

    private fun createFreshKey(): SecretKey =
        try { buildKey(useStrongBox = true) } catch (e: Exception) { buildKey(useStrongBox = false) }

    private fun promptInfo(): BiometricPrompt.PromptInfo =
        BiometricPrompt.PromptInfo.Builder()
            .setTitle("Unlock ZeroKey")
            .setSubtitle("Use your biometrics to open your vault")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .setNegativeButtonText("Use master password")
            .build()

    /**
     * ENROLL: store a biometric-wrapped copy of the raw vault key. Vault must be unlocked.
     * Prompts biometric once to confirm.
     */
    fun enroll(activity: FragmentActivity, rawVaultKey: ByteArray, onResult: (Boolean) -> Unit) {
        val cipher = Cipher.getInstance(AES_MODE)
        try {
            clear() // start fresh so a brand-new key is generated
            cipher.init(Cipher.ENCRYPT_MODE, createFreshKey())
        } catch (e: Exception) {
            PrivacyLogger.e("BiometricUnlock", "Enroll init failed: ${e.message}")
            onResult(false); return
        }
        val bp = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val c = result.cryptoObject?.cipher ?: return onResult(false)
                        val ct = c.doFinal(rawVaultKey)
                        prefs.edit()
                            .putString(KEY_BLOB, Base64.encodeToString(ct, Base64.NO_WRAP))
                            .putString(KEY_IV, Base64.encodeToString(c.iv, Base64.NO_WRAP))
                            .apply()
                        onResult(true)
                    } catch (e: Exception) {
                        PrivacyLogger.e("BiometricUnlock", "Enroll encrypt failed")
                        onResult(false)
                    }
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) = onResult(false)
            })
        bp.authenticate(promptInfo(), BiometricPrompt.CryptoObject(cipher))
    }

    /**
     * UNLOCK: prompt biometric and return the raw vault key bytes on success, else null.
     * Caller MUST zero the returned array after use.
     */
    fun unlock(activity: FragmentActivity, onResult: (ByteArray?) -> Unit) {
        val blobB64 = prefs.getString(KEY_BLOB, null)
        val ivB64 = prefs.getString(KEY_IV, null)
        if (blobB64 == null || ivB64 == null) { onResult(null); return }

        val blob = Base64.decode(blobB64, Base64.NO_WRAP)
        val iv = Base64.decode(ivB64, Base64.NO_WRAP)

        val cipher = Cipher.getInstance(AES_MODE)
        try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val key = ks.getKey(BIO_KEY_ALIAS, null) as? SecretKey ?: run { onResult(null); return }
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_LENGTH, iv))
        } catch (e: KeyPermanentlyInvalidatedException) {
            // Biometrics changed -> wrapped key is gone for good. Fall back to master password.
            clear(); onResult(null); return
        } catch (e: Exception) {
            PrivacyLogger.e("BiometricUnlock", "Unlock init failed: ${e.message}")
            onResult(null); return
        }
        val bp = BiometricPrompt(activity, ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    try {
                        val c = result.cryptoObject?.cipher ?: return onResult(null)
                        onResult(c.doFinal(blob))
                    } catch (e: Exception) {
                        PrivacyLogger.e("BiometricUnlock", "Unlock decrypt failed")
                        onResult(null)
                    }
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) = onResult(null)
            })
        bp.authenticate(promptInfo(), BiometricPrompt.CryptoObject(cipher))
    }
}
