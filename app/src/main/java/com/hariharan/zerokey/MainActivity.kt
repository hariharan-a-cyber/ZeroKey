package com.hariharan.zerokey

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.compose.BackHandler
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
import com.google.firebase.firestore.FirebaseFirestore
import com.hariharan.zerokey.data.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.sync.VaultSerializer
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.security.*
import com.hariharan.zerokey.sync.*
import com.hariharan.zerokey.sharing.*
import com.hariharan.zerokey.emergency.*
import com.hariharan.zerokey.ui.screens.*
import com.hariharan.zerokey.ui.theme.ZerokeyTheme
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import com.hariharan.zerokey.viewmodel.PasswordViewModelFactory
import com.hariharan.zerokey.viewmodel.SyncViewModel

class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
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
                    ExitBackHandler()
                    AuthScreen(
                        authenticator = authenticator,
                        onAuthSuccess = { isAuthenticated = true }
                    )
                } else {
                    VaultContent(authAttemptManager, authenticator)
                }
            }
        }
    }

    override fun onPause() {
        super.onPause()
        clearClipboard()
    }

    override fun onDestroy() {
        super.onDestroy()
        clearClipboard()
    }

    private fun clearClipboard() {
        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        if (clipboard.hasPrimaryClip()) {
            val description = clipboard.primaryClipDescription
            val label = description?.label?.toString() ?: ""
            if (label == "password" || label == "generated_password" || label == "zerokey_password" || label.contains("password", ignoreCase = true)) {
                val clip = ClipData.newPlainText("", "")
                clipboard.setPrimaryClip(clip)
            }
        }
    }

    @Composable
    fun VaultContent(authAttemptManager: AuthAttemptManager, authenticator: FirebaseAuthenticator) {
        val database = PasswordDatabase.getDatabase(applicationContext)
        val repository = PasswordRepository(database.passwordDao())
        val auditLogManager = AuditLogManager(database.auditLogDao())
        val backupManager = VaultBackupManager(repository, VaultSerializer())
        
        // --- Dependency Injection for Advanced Features ---
        val firestore = FirebaseFirestore.getInstance()
        val cryptoEngine = CryptoEngine()
        val hmacEngine = HmacEngine()
        val conflictResolver = VaultConflictResolver(cryptoEngine, hmacEngine)
        
        val syncManager = DeviceSyncManager(firestore, cryptoEngine, hmacEngine, conflictResolver)
        val shareManager = CredentialShareManager(firestore, hmacEngine)
        
        // Using fully qualified name to avoid ambiguity between security and emergency packages
        val emergencyManager = com.hariharan.zerokey.emergency.EmergencyAccessManager(
            firestore, 
            cryptoEngine, 
            object : EmergencyNotificationService {
                override suspend fun notifyOwnerOfRequest(ownerId: String, contactEmail: String, cancelDeadline: Long) {}
                override suspend fun notifyRequestCancelled(contactEmail: String) {}
                override suspend fun notifyAccessGranted(ownerId: String, contactEmail: String) {}
            }
        )

        val viewModel: PasswordViewModel = viewModel(
            factory = PasswordViewModelFactory(
                repository = repository,
                auditLogManager = auditLogManager,
                backupManager = backupManager,
                syncManager = syncManager,
                shareManager = shareManager,
                emergencyManager = emergencyManager
            )
        )

        // SyncViewModel integration
        val syncViewModel: SyncViewModel = viewModel(
            factory = object : androidx.lifecycle.ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T {
                    return SyncViewModel(repository, syncManager) as T
                }
            }
        )

        var isLocked by remember { mutableStateOf(true) }
        val lifecycleOwner = LocalLifecycleOwner.current

        DisposableEffect(lifecycleOwner) {
            val observer = LifecycleEventObserver { _, event ->
                if (event == Lifecycle.Event.ON_STOP) {
                    // Lock the UI when app goes to background
                    isLocked = true
                }
            }
            lifecycleOwner.lifecycle.addObserver(observer)
            onDispose {
                lifecycleOwner.lifecycle.removeObserver(observer)
                // Note: We no longer call MasterPasswordManager.lockVault() here because
                // it causes session loss during configuration changes (like rotation).
                // The session will be cleared when the process is killed or via explicit logout.
            }
        }

        if (isLocked) {
            BiometricLockScreen(authAttemptManager) {
                isLocked = false
            }
        } else {
            ZeroKeyApp(viewModel, syncViewModel, authenticator.uid ?: "guest")
        }
    }
}

/**
 * Helper composable to handle "Double Back to Exit" logic.
 */
@Composable
fun ExitBackHandler() {
    val context = LocalContext.current
    var backPressedTime by remember { mutableStateOf(0L) }

    BackHandler {
        val now = System.currentTimeMillis()
        if (backPressedTime + 2000 > now) {
            (context as? FragmentActivity)?.finish()
        } else {
            Toast.makeText(context, "Press back again to exit", Toast.LENGTH_SHORT).show()
            backPressedTime = now
        }
    }
}

@Composable
fun BiometricLockScreen(authManager: AuthAttemptManager, onAuthenticated: () -> Unit) {
    val context = LocalContext.current as FragmentActivity
    ExitBackHandler()

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
fun ZeroKeyApp(
    viewModel: PasswordViewModel, 
    syncViewModel: SyncViewModel,
    userId: String
) {
    var currentScreen by remember { mutableStateOf("vault") }
    var generatedPasswordToUse by remember { mutableStateOf<String?>(null) }
    
    val context = LocalContext.current
    var backPressedTime by remember { mutableStateOf(0L) }

    // Custom BackHandler for main app navigation
    BackHandler {
        if (currentScreen != "vault") {
            // Navigate back to Home (Vault) if in any other screen/tab
            currentScreen = "vault"
            backPressedTime = 0L // Reset exit timer when navigating back to vault
        } else {
            // Double-back to exit logic if already on Home screen
            val now = System.currentTimeMillis()
            if (backPressedTime + 2000 > now) {
                (context as? FragmentActivity)?.finish()
            } else {
                Toast.makeText(context, "Press back again to exit", Toast.LENGTH_SHORT).show()
                backPressedTime = now
            }
        }
    }

    when (currentScreen) {
        "vault" -> VaultScreen(
            viewModel = viewModel,
            onAddClick = { currentScreen = "add_password" },
            onSecurityActivityClick = { currentScreen = "security_activity" },
            onPasswordHealthClick = { currentScreen = "password_health" },
            onSecurityDashboardClick = { currentScreen = "security_dashboard" },
            onSharingClick = { currentScreen = "credential_sharing" },
            onSyncClick = { currentScreen = "cloud_sync" }
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
        "cloud_sync" -> SyncScreen(
            viewModel = syncViewModel,
            onBack = { currentScreen = "vault" },
            userId = userId
        )
    }
}
