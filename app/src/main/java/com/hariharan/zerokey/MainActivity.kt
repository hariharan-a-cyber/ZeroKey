package com.hariharan.zerokey

import android.os.Bundle
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricPrompt
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.hariharan.zerokey.data.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.security.EncryptionManager
import com.hariharan.zerokey.ui.screens.AddPasswordScreen
import com.hariharan.zerokey.ui.screens.VaultScreen
import com.hariharan.zerokey.ui.theme.ZerokeyTheme
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import com.hariharan.zerokey.viewmodel.PasswordViewModelFactory

class MainActivity : FragmentActivity() {
    
    private var lastBackgroundTime: Long = 0

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // 1. Screenshot Blocking - Protection against screen recording and snapshots
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        
        enableEdgeToEdge()
        setContent {
            ZerokeyTheme {
                val database = PasswordDatabase.getDatabase(applicationContext)
                val repository = PasswordRepository(database.passwordDao(), EncryptionManager)
                val viewModel: PasswordViewModel = viewModel(
                    factory = PasswordViewModelFactory(repository)
                )

                var isLocked by remember { mutableStateOf(true) }
                val lifecycleOwner = LocalLifecycleOwner.current

                // 3. Auto Lock logic - Locks the vault if app is in background > 30 seconds
                DisposableEffect(lifecycleOwner) {
                    val observer = LifecycleEventObserver { _, event ->
                        when (event) {
                            Lifecycle.Event.ON_STOP -> {
                                lastBackgroundTime = System.currentTimeMillis()
                            }
                            Lifecycle.Event.ON_START -> {
                                if (lastBackgroundTime != 0L && 
                                    System.currentTimeMillis() - lastBackgroundTime > 30000) {
                                    isLocked = true
                                }
                            }
                            else -> {}
                        }
                    }
                    lifecycleOwner.lifecycle.addObserver(observer)
                    onDispose {
                        lifecycleOwner.lifecycle.removeObserver(observer)
                    }
                }

                if (isLocked) {
                    BiometricLockScreen(onAuthenticated = { isLocked = false })
                } else {
                    ZeroKeyApp(viewModel)
                }
            }
        }
    }
}

@Composable
fun BiometricLockScreen(onAuthenticated: () -> Unit) {
    val context = LocalContext.current as FragmentActivity
    val executor = ContextCompat.getMainExecutor(context)
    
    val biometricPrompt = BiometricPrompt(context, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onAuthenticated()
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                // In a production app, handle errors (e.g. show a "Try Again" button)
            }
        })

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("ZeroKey Secure Unlock")
        .setSubtitle("Authenticate to access your encrypted vault")
        .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                 androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        .build()

    LaunchedEffect(Unit) {
        biometricPrompt.authenticate(promptInfo)
    }
}

@Composable
fun ZeroKeyApp(viewModel: PasswordViewModel) {
    var currentScreen by remember { mutableStateOf("vault") }

    if (currentScreen == "vault") {
        VaultScreen(
            viewModel = viewModel,
            onAddClick = { currentScreen = "add_password" }
        )
    } else {
        AddPasswordScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" }
        )
    }
}
