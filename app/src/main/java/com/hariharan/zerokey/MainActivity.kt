package com.hariharan.zerokey

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.hariharan.zerokey.data.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.sync.VaultSerializer
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.security.*
import com.hariharan.zerokey.ui.screens.*
import com.hariharan.zerokey.ui.theme.ZerokeyTheme
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import com.hariharan.zerokey.viewmodel.PasswordViewModelFactory

class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Requirement 7: Screen Security - Block screenshots and recent-app previews
        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        
        enableEdgeToEdge()
        val authAttemptManager = AuthAttemptManager(this)
        val authenticator = FirebaseAuthenticator()

        setContent {
            ZerokeyTheme {
                var isAuthenticated by remember { mutableStateOf(authenticator.isAuthenticated) }
                
                if (!isAuthenticated) {
                    AuthScreen(
                        authenticator = authenticator,
                        onAuthSuccess = { isAuthenticated = true }
                    )
                } else {
                    VaultContent(authAttemptManager)
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        // Requirement 6: Clear clipboard when app goes to background
        clearClipboard()
    }

    private fun clearClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = ClipData.newPlainText("", "")
        clipboard.setPrimaryClip(clip)
    }

    @Composable
    fun VaultContent(authAttemptManager: AuthAttemptManager) {
        val database = PasswordDatabase.getDatabase(applicationContext)
        val repository = PasswordRepository(database.passwordDao())
        val auditLogManager = AuditLogManager(database.auditLogDao())
        val backupManager = VaultBackupManager(repository, VaultSerializer())
        
        val viewModel: PasswordViewModel = viewModel(
            factory = PasswordViewModelFactory(repository, auditLogManager, backupManager)
        )

        var isLocked by remember { mutableStateOf(true) }
        val lifecycleOwner = LocalLifecycleOwner.current

        DisposableEffect(lifecycleOwner) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP) {
                    isLocked = true
                    // Requirement 5: Wipe memory (session key) when app stops
                    MasterPasswordManager.lockVault()
                }
            }
            lifecycleOwner.lifecycle.addObserver(observer)
            onDispose {
                lifecycleOwner.lifecycle.removeObserver(observer)
            }
        }

        if (isLocked) {
            BiometricLockScreen(authAttemptManager) {
                isLocked = false
            }
        } else {
            ZeroKeyApp(viewModel)
        }
    }
}

@Composable
fun BiometricLockScreen(authManager: AuthAttemptManager, onAuthenticated: () -> Unit) {
    val context = LocalContext.current as FragmentActivity

    if (authManager.isLockedOut()) {
        Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
            val remaining = authManager.getRemainingLockoutTime() / 1000
            Text("Too many attempts. Please try again in $remaining seconds.")
        }
        return
    }

    val executor = ContextCompat.getMainExecutor(context)
    val biometricPrompt = BiometricPrompt(context, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                authManager.resetAttempts()
                // In a real app, you'd perform key derivation here with the master password
                // This is a simplified flow for existing logic integration
                onAuthenticated()
            }
            
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                super.onAuthenticationError(errorCode, errString)
                authManager.recordFailedAttempt()
                Toast.makeText(context, "Authentication error: $errString", Toast.LENGTH_SHORT).show()
            }
        })

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("ZeroKey Unlock")
        .setSubtitle("Authenticate to access your vault")
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
    var generatedPasswordToUse by remember { mutableStateOf<String?>(null) }

    when (currentScreen) {
        "vault" -> VaultScreen(
            viewModel = viewModel,
            onAddClick = { currentScreen = "add_password" },
            onSecurityActivityClick = { currentScreen = "security_activity" },
            onPasswordHealthClick = { currentScreen = "password_health" },
            onSecurityDashboardClick = { currentScreen = "security_dashboard" },
            onSharingClick = { currentScreen = "credential_sharing" }
        )
        "add_password" -> AddPasswordScreen(
            viewModel = viewModel,
            initialPassword = generatedPasswordToUse ?: "",
            onBack = { 
                currentScreen = "vault"
                generatedPasswordToUse = null
            },
            onGenerateClick = { currentScreen = "generator" }
        )
        "security_activity" -> SecurityActivityScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" }
        )
        "password_health" -> PasswordHealthScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" }
        )
        "generator" -> PasswordGeneratorScreen(
            onBack = { currentScreen = "add_password" },
            onUsePassword = { 
                generatedPasswordToUse = it
                currentScreen = "add_password"
            }
        )
        "security_dashboard" -> SecurityDashboardScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" }
        )
        "credential_sharing" -> CredentialSharingScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" }
        )
    }
}
