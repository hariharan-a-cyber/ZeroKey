package com.hariharan.zerokey.security

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.service.autofill.Dataset
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.hariharan.zerokey.R
import com.hariharan.zerokey.core.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.core.common.SensitiveDataManager
import kotlinx.coroutines.runBlocking

import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.security.MasterPasswordManager

/**
 * Invisible activity that handles Biometric Authentication for Autofill.
 * Decrypts the password ONLY after successful authentication.
 */
@AndroidEntryPoint
class AutofillAuthActivity : FragmentActivity() {

    @Inject lateinit var masterPasswordManager: MasterPasswordManager
    @Inject lateinit var encryptionManager: EncryptionManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val itemId = intent.getIntExtra("itemId", -1)
        val username = intent.getStringExtra("username")
        
        val usernameId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra("usernameId", AutofillId::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra("usernameId")
        }

        val passwordId = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            intent.getParcelableExtra("passwordId", AutofillId::class.java)
        } else {
            @Suppress("DEPRECATION")
            intent.getParcelableExtra("passwordId")
        }

        if (itemId == -1 || username == null || usernameId == null || passwordId == null) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    
                    val database = PasswordDatabase.getDatabase(this@AutofillAuthActivity)
                    val repository = PasswordRepository(
                        database.passwordDao(), 
                        database.vaultMetadataDao(),
                        masterPasswordManager,
                        encryptionManager
                    )
                    
                    val password = runBlocking {
                        repository.getPasswordById(itemId)?.password
                    }

                    if (password != null) {
                        val replyIntent = Intent().apply {
                            val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                                setTextViewText(android.R.id.text1, username)
                            }

                            val dataset = Dataset.Builder(presentation)
                                .setValue(usernameId, AutofillValue.forText(username))
                                .setValue(passwordId, AutofillValue.forText(password))
                                .build()

                            putExtra(android.view.autofill.AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)
                        }
                        
                        setResult(Activity.RESULT_OK, replyIntent)
                        
                        // Clear password from memory
                        val passChars = password.toCharArray()
                        SensitiveDataManager.clearSensitiveData(passChars)
                    } else {
                        setResult(Activity.RESULT_CANCELED)
                    }
                    finish()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    setResult(Activity.RESULT_CANCELED)
                    finish()
                }
            })

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ZeroKey Autofill")
            .setSubtitle("Confirm to fill your credentials")
            .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                     androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
            .build()

        biometricPrompt.authenticate(promptInfo)
    }
}
