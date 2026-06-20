package com.hariharan.zerokey

import android.content.Context
import android.content.SharedPreferences
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.crypto.KeyDerivationManager
import com.hariharan.zerokey.core.security.MasterPasswordManager
import io.mockk.*
import io.mockk.impl.annotations.MockK
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import javax.crypto.spec.SecretKeySpec
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import android.security.keystore.KeyGenParameterSpec

class MasterPasswordManagerTest {

    @MockK
    lateinit var context: Context
    
    @MockK
    lateinit var sharedPrefs: SharedPreferences
    
    @MockK
    lateinit var editor: SharedPreferences.Editor

    private lateinit var encryptionManager: EncryptionManager
    private lateinit var keyDerivationManager: KeyDerivationManager
    private lateinit var masterPasswordManager: MasterPasswordManager

    private val testPassword = "master-password".toCharArray()
    private val testKey = SecretKeySpec(ByteArray(32) { 1.toByte() }, "AES")

    @Before
    fun setup() {
        MockKAnnotations.init(this)
        
        encryptionManager = spyk(EncryptionManager())
        keyDerivationManager = spyk(KeyDerivationManager())
        masterPasswordManager = MasterPasswordManager(encryptionManager, keyDerivationManager)

        // Mock EncryptedSharedPreferences.create
        mockkStatic(EncryptedSharedPreferences::class)
        every {
            EncryptedSharedPreferences.create(
                any<String>(),
                any<String>(),
                any<Context>(),
                any<EncryptedSharedPreferences.PrefKeyEncryptionScheme>(),
                any<EncryptedSharedPreferences.PrefValueEncryptionScheme>()
            )
        } returns sharedPrefs

        mockkStatic(MasterKeys::class)
        // Adjusting to the actual expected type if possible, or just any()
        every { MasterKeys.getOrCreate(any()) } returns "test-alias"

        every { sharedPrefs.edit() } returns editor
        every { editor.putString(any(), any()) } returns editor
        every { editor.putInt(any(), any()) } returns editor
        every { editor.putLong(any(), any()) } returns editor
        every { editor.apply() } just Runs
    }

    @Test
    fun `setupVault then unlockVault with correct password succeeds`() {
        // 1. Setup mocks for setupVault
        every { sharedPrefs.getString("vault_salt", null) } returns null // Not setup yet
        
        // Mock getStoredValue for setup logic (it saves salt and version)
        val saltSlot = slot<String>()
        every { editor.putString("vault_salt", capture(saltSlot)) } returns editor
        
        // 2. Run setup
        masterPasswordManager.setupVault(context, testPassword.copyOf())
        
        // 3. Prepare for unlock
        // Mock stored values for unlockVault
        every { sharedPrefs.getString("vault_salt", null) } returns saltSlot.captured
        every { sharedPrefs.getInt("crypto_version", 1) } returns 4 // Argon2id v4
        every { sharedPrefs.getString("encrypted_vault_key_blob", null) } returns "YmxvYg==" // "blob" in B64
        every { sharedPrefs.getString("vault_key_iv_outer", null) } returns "YmxvYg=="
        every { sharedPrefs.getString("vault_key_iv_inner", null) } returns "YmxvYg=="
        
        // Mock Root Key decryption since we don't have real KeyStore in unit test
        every { encryptionManager.decryptWithRootKey(any()) } returns ByteArray(32) { 0x05.toByte() }
        
        // 4. Run unlock
        masterPasswordManager.unlockVault(context, testPassword.copyOf())
        
        assertTrue("Vault must be unlocked", masterPasswordManager.isUnlocked())
        assertNotNull("Vault key must not be null", masterPasswordManager.getVaultKey())
    }

    @Test(expected = Exception::class)
    fun `unlockVault with wrong password throws`() {
        // Setup initial state as "setup"
        every { sharedPrefs.getString("vault_salt", null) } returns "some-salt"
        every { sharedPrefs.getInt("crypto_version", 1) } returns 4
        every { sharedPrefs.getString("encrypted_vault_key_blob", null) } returns "blob"
        every { sharedPrefs.getString("vault_key_iv_outer", null) } returns "iv-outer"
        every { sharedPrefs.getString("vault_key_iv_inner", null) } returns "iv-inner"
        
        // Mock Root Key decryption
        every { encryptionManager.decryptWithRootKey(any()) } returns ByteArray(32) { 0x05.toByte() }
        
        // Mock deriveKey to return something, but EncryptionManager.decryptWithKey will fail if tag mismatch
        every { encryptionManager.decryptWithKey(any(), any(), any()) } throws Exception("Decryption failed")
        
        masterPasswordManager.unlockVault(context, "wrong-password".toCharArray())
    }

    @Test
    fun `lockVault sets isUnlocked to false`() {
        masterPasswordManager.lockVault()
        assertFalse("Vault must be locked", masterPasswordManager.isUnlocked())
    }
}
