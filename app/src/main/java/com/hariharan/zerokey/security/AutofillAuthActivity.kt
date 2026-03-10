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

/**
 * Invisible activity that handles Biometric Authentication for Autofill.
 * Ensures passwords are only decrypted after successful user authentication.
 */
class AutofillAuthActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val username = intent.getStringExtra("username")
        val password = intent.getStringExtra("password")
        
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

        if (username == null || password == null || usernameId == null || passwordId == null) {
            setResult(Activity.RESULT_CANCELED)
            finish()
            return
        }

        val executor = ContextCompat.getMainExecutor(this)
        val biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    
                    val replyIntent = Intent().apply {
                        val presentation = RemoteViews(packageName, R.layout.autofill_suggestion).apply {
                            setTextViewText(R.id.autofill_username, username)
                        }

                        val dataset = Dataset.Builder()
                            .setValue(usernameId, AutofillValue.forText(username), presentation)
                            .setValue(passwordId, AutofillValue.forText(password), presentation)
                            .build()

                        // Explicitly using the full path to resolve compilation ambiguity
                        putExtra(android.view.autofill.AutofillManager.EXTRA_AUTHENTICATION_RESULT, dataset)
                    }
                    
                    setResult(Activity.RESULT_OK, replyIntent)
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
