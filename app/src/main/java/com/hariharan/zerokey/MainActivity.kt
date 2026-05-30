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
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.lifecycle.viewmodel.compose.viewModel
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.FirebaseFirestoreSettings
import com.google.firebase.firestore.PersistentCacheSettings
import com.hariharan.zerokey.data.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.sync.VaultSerializer
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.security.*
import com.hariharan.zerokey.sync.*
import com.hariharan.zerokey.sharing.*
import com.hariharan.zerokey.emergency.*
import com.hariharan.zerokey.ui.screens.*
import com.hariharan.zerokey.ui.theme.ZeroKeyTheme
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import com.hariharan.zerokey.viewmodel.PasswordViewModelFactory
import com.hariharan.zerokey.viewmodel.SyncViewModel
import com.hariharan.zerokey.utils.PrivacyLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : FragmentActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        // Privacy Hardening: Global Crash Sanitizer
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            PrivacyLogger.e("CRASH", "Uncaught Exception in ${thread.name}: ${PrivacyLogger.sanitizeError(throwable.message)}", throwable)
        }

        window.setFlags(
            WindowManager.LayoutParams.FLAG_SECURE,
            WindowManager.LayoutParams.FLAG_SECURE
        )
        
        enableEdgeToEdge()
        val authAttemptManager = AuthAttemptManager(this)
        val authenticator = FirebaseAuthenticator()

        setContent {
            ZeroKeyTheme {
                var isAuthenticated by remember { mutableStateOf(authenticator.isAuthenticated) }
                // Use a key-based state that we can refresh on resume
                var vaultCheckKey by remember { mutableStateOf(0) }
                val isVaultUnlocked = remember(vaultCheckKey) { MasterPasswordManager.isUnlocked() }
                
                // Security Hardening: Check device integrity
                val context = LocalContext.current
                val securityStatus = remember { SecurityHardening.checkDeviceSecurity(context) }
                val keySecurity = remember { EncryptionManager.getKeySecurityLevel() }
                
                var showSecurityWarning by remember { 
                    mutableStateOf(securityStatus.isCompromised || 
                                   securityStatus.accessibilityRisk == SecurityHardening.RiskLevel.HIGH ||
                                   keySecurity == EncryptionManager.KeySecurityLevel.SOFTWARE) 
                }

                if (showSecurityWarning) {
                    AlertDialog(
                        onDismissRequest = { showSecurityWarning = false },
                        icon = { Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error) },
                        title = { 
                            Text(if (securityStatus.isFridaDetected) "Critical Tamper Detected" else if (securityStatus.isCompromised) "Security Advisory" else "Security Advisory") 
                        },
                        text = { 
                            val message = StringBuilder()
                            if (securityStatus.isRooted) message.append("• Your device is rooted.\n")
                            if (securityStatus.isDebuggerAttached) message.append("• A debugger is attached.\n")
                            if (securityStatus.isFridaDetected) message.append("• Active runtime hooks (Frida) detected.\n")
                            if (securityStatus.accessibilityRisk == SecurityHardening.RiskLevel.HIGH) {
                                message.append("• High-risk accessibility services detected: ${securityStatus.highRiskServices.joinToString(", ")}. These apps can read your screen.\n")
                            }
                            if (keySecurity == EncryptionManager.KeySecurityLevel.SOFTWARE) {
                                message.append("• No secure hardware detected for key storage.\n")
                            }
                            
                            val footer = if (securityStatus.isFridaDetected)
                                "\nSEVERE TAMPER DETECTED. Vault access is strictly limited for your safety."
                            else if (securityStatus.isCompromised)
                                "\nUsing a password manager in this environment is HIGHLY dangerous." 
                            else "\nWe recommend reviewing these settings for maximum privacy."

                            Text(message.toString() + footer) 
                        },
                        confirmButton = {
                            Button(onClick = { showSecurityWarning = false }) { Text("I Understand") }
                        }
                    )
                }

                if (!isAuthenticated || !isVaultUnlocked) {
                    ExitBackHandler()
                    AuthScreen(
                        authenticator = authenticator,
                        onAuthSuccess = { 
                            isAuthenticated = true
                            MasterPasswordManager.authorizeAutofill()
                            vaultCheckKey++
                        }
                    )
                } else {
                    VaultContent(authAttemptManager, authenticator, onRefreshVault = { vaultCheckKey++ })
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
            if (label == "password" || label == "generated_password" || label == "ZeroKey_Password" || label.contains("password", ignoreCase = true)) {
                val clip = ClipData.newPlainText("", "")
                clipboard.setPrimaryClip(clip)
            }
        }
    }

    @Composable
    fun VaultContent(authAttemptManager: AuthAttemptManager, authenticator: FirebaseAuthenticator, onRefreshVault: () -> Unit) {
        val database = PasswordDatabase.getDatabase(applicationContext)
        val repository = PasswordRepository(database.passwordDao(), database.vaultMetadataDao())
        val auditLogManager = AuditLogManager(database.auditLogDao())
        val backupManager = VaultBackupManager(repository, VaultSerializer())
        
        // --- Hard Reset Firestore Settings ---
        val firestore = FirebaseFirestore.getInstance()
        val settings = FirebaseFirestoreSettings.Builder()
            .setLocalCacheSettings(PersistentCacheSettings.newBuilder().build())
            .build()
        firestore.firestoreSettings = settings

        val cryptoEngine = CryptoEngine()
        val hmacEngine = HmacEngine()
        val conflictResolver = VaultConflictResolver(cryptoEngine, hmacEngine)
        val deviceTrustManager = DeviceTrustManager(applicationContext, firestore)
        
        val syncManager = DeviceSyncManager(firestore, cryptoEngine, hmacEngine, conflictResolver, deviceTrustManager)
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
                emergencyManager = emergencyManager,
                deviceTrustManager = deviceTrustManager
            )
        )

        // SyncViewModel integration
        val syncViewModel: SyncViewModel = viewModel(
            factory = object : androidx.lifecycle.ViewModelProvider.Factory {
                @Suppress("UNCHECKED_CAST")
                override fun <T : androidx.lifecycle.ViewModel> create(modelClass: Class<T>): T {
                    return SyncViewModel(application, repository, syncManager) as T
                }
            }
        )

        var isLocked by remember { mutableStateOf(true) }
        val lifecycleOwner = LocalLifecycleOwner.current
        val scope = rememberCoroutineScope()

        DisposableEffect(lifecycleOwner) {
            val observer = LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_STOP -> {
                        // Lock the UI
                        isLocked = true
                        
                        // Aggressive key purging only if user policy allows it
                        if (!isChangingConfigurations && MasterPasswordManager.shouldLockOnExit(applicationContext)) {
                            MasterPasswordManager.lockVault()
                            viewModel.lockVault()
                        }
                        onRefreshVault()
                    }
                    Lifecycle.Event.ON_RESUME -> {
                        // Security Hardening: Active Revocation Check
                        scope.launch {
                            val uid = authenticator.uid ?: "guest"
                            if (MasterPasswordManager.isUnlocked() && !deviceTrustManager.isCurrentDeviceTrusted(uid)) {
                                withContext(Dispatchers.Main) {
                                    MasterPasswordManager.lockVault()
                                    viewModel.lockVault()
                                    onRefreshVault()
                                    Toast.makeText(applicationContext, "Access Revoked: This device is no longer trusted.", Toast.LENGTH_LONG).show()
                                }
                            } else {
                                withContext(Dispatchers.Main) {
                                    onRefreshVault()
                                }
                            }
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
            BiometricLockScreen(authAttemptManager) {
                isLocked = false
            }
        } else {
            val uid = authenticator.uid ?: "guest"
            LaunchedEffect(uid) {
                viewModel.setUserId(uid)
            }
            ZeroKeyApp(viewModel, syncViewModel, uid)
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        MasterPasswordManager.onTrimMemory(level)
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
    var isAuthenticating by remember { mutableStateOf(false) }

    ExitBackHandler()

    if (authManager.isLockedOut()) {
        Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface), contentAlignment = Alignment.Center) {
            val remaining = authManager.getRemainingLockoutTime() / 1000
            Text("Too many attempts. Please try again in $remaining seconds.", textAlign = TextAlign.Center)
        }
        return
    }

    Box(
        modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(
                Icons.Default.Lock,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(modifier = Modifier.height(24.dp))
            Button(onClick = { isAuthenticating = true }) {
                Text("Unlock ZeroKey")
            }
        }
    }

    if (isAuthenticating || !authManager.isLockedOut()) {
        val executor = ContextCompat.getMainExecutor(context)
        val biometricPrompt = remember {
            BiometricPrompt(context, executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                        super.onAuthenticationSucceeded(result)
                        isAuthenticating = false
                        authManager.resetAttempts()
                        onAuthenticated()
                    }
                    
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                        super.onAuthenticationError(errorCode, errString)
                        isAuthenticating = false
                        if (errorCode != BiometricPrompt.ERROR_USER_CANCELED && errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                            authManager.recordFailedAttempt()
                            Toast.makeText(context, "Authentication error: $errString", Toast.LENGTH_SHORT).show()
                        }
                    }

                    override fun onAuthenticationFailed() {
                        super.onAuthenticationFailed()
                        // This is for "Wrong Fingerprint" (not a terminal error)
                    }
                })
        }

        val promptInfo = remember {
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("ZeroKey Unlock")
                .setSubtitle("Authenticate to access your vault")
                .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                         androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
                .build()
        }

        LaunchedEffect(isAuthenticating) {
            // Automatically prompt on first enter or when button clicked
            biometricPrompt.authenticate(promptInfo)
        }
    }
}

@Composable
fun ZeroKeyApp(
    viewModel: PasswordViewModel, 
    syncViewModel: SyncViewModel,
    userId: String
) {
    var currentScreen by remember { mutableStateOf("vault") }
    var selectedItemId by remember { mutableStateOf<Int?>(null) }
    var generatedPasswordToUse by remember { mutableStateOf<String?>(null) }
    
    val context = LocalContext.current
    var backPressedTime by remember { mutableStateOf(0L) }

    // Custom BackHandler for main app navigation
    BackHandler {
        if (currentScreen != "vault") {
            // Navigate back to Home (Vault) if in any other screen/tab
            if (currentScreen == "password_details") {
                currentScreen = "security_dashboard"
            } else {
                currentScreen = "vault"
            }
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
            onSyncClick = { currentScreen = "cloud_sync" },
            onSettingsClick = { currentScreen = "settings" }
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
            onBack = { currentScreen = "vault" },
            onFixCredential = { id ->
                selectedItemId = id
                currentScreen = "password_details"
            }
        )
        "password_details" -> selectedItemId?.let { id ->
            PasswordDetailScreen(
                itemId = id,
                viewModel = viewModel,
                onBack = { currentScreen = "security_dashboard" },
                onDeleted = { currentScreen = "security_dashboard" }
            )
        }
        "credential_sharing" -> CredentialSharingScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" },
            userId = userId
        )
        "cloud_sync" -> SyncScreen(
            viewModel = syncViewModel,
            onBack = { currentScreen = "vault" },
            userId = userId
        )
        "settings" -> SettingsScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "vault" },
            onManageDevices = { currentScreen = "device_management" }
        )
        "device_management" -> DeviceManagementScreen(
            viewModel = viewModel,
            onBack = { currentScreen = "settings" }
        )
    }
}
