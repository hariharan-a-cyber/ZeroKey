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
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.compose.LocalLifecycleOwner
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import androidx.navigation.navArgument
import com.hariharan.zerokey.ui.navigation.Screen
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.FirebaseFirestoreSettings
import com.google.firebase.firestore.PersistentCacheSettings
import com.hariharan.zerokey.core.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.data.sync.VaultSerializer
import com.hariharan.zerokey.data.backup.VaultBackupManager
import com.hariharan.zerokey.security.*
import com.hariharan.zerokey.core.security.*
import com.hariharan.zerokey.core.crypto.*
import com.hariharan.zerokey.sync.*
import com.hariharan.zerokey.sharing.*
import com.hariharan.zerokey.emergency.*
import com.hariharan.zerokey.ui.screens.*
import com.hariharan.zerokey.ui.theme.ZeroKeyTheme
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import com.hariharan.zerokey.viewmodel.SyncViewModel
import com.hariharan.zerokey.core.common.PrivacyLogger
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

@AndroidEntryPoint
class MainActivity : FragmentActivity() {

    @Inject lateinit var masterPasswordManager: MasterPasswordManager
    @Inject lateinit var encryptionManager: EncryptionManager
    @Inject lateinit var hmacEngine: HmacEngine
    @Inject lateinit var keyDerivationManager: KeyDerivationManager
    @Inject lateinit var breachMonitor: BreachMonitor
    @Inject lateinit var authAttemptManager: AuthAttemptManager
    @Inject lateinit var passwordDatabase: PasswordDatabase
    @Inject lateinit var vaultRepository: PasswordRepository
    @Inject lateinit var auditLogManager: AuditLogManager
    @Inject lateinit var deviceSyncManager: DeviceSyncManager
    @Inject lateinit var credentialShareManager: CredentialShareManager
    @Inject lateinit var deviceTrustManager: DeviceTrustManager
    @Inject lateinit var biometricVaultUnlockManager: BiometricVaultUnlockManager
    @Inject lateinit var authenticator: FirebaseAuthenticator

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
        val authenticator = this.authenticator

        setContent {
            ZeroKeyTheme {
                var isAuthenticated by remember { mutableStateOf(authenticator.isAuthenticated) }
                // Use a key-based state that we can refresh on resume
                var vaultCheckKey by remember { mutableStateOf(0) }
                val isVaultUnlocked = remember(vaultCheckKey) { masterPasswordManager.isUnlocked() }
                
                // Security Hardening: Check device integrity
                val context = LocalContext.current
                val securityStatus = remember { SecurityHardening.checkDeviceSecurity(context) }
                val keySecurity = remember { encryptionManager.getKeySecurityLevel() }
                
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
                        masterPasswordManager = masterPasswordManager,
                        authAttemptManager = authAttemptManager,
                        biometricUnlockManager = biometricVaultUnlockManager,
                        onAuthSuccess = { 
                            isAuthenticated = true
                            masterPasswordManager.authorizeAutofill()
                            // Register this device as trusted so remote-revocation can work later.
                            lifecycleScope.launch {
                                try {
                                    authenticator.uid?.let { deviceTrustManager.registerCurrentDevice(it) }
                                } catch (_: Exception) { /* offline is fine; not required to unlock */ }
                            }
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
        val viewModel: PasswordViewModel = hiltViewModel()
        val syncViewModel: SyncViewModel = hiltViewModel()
        
        val deviceTrustManager = this.deviceTrustManager

        var isLocked by remember { mutableStateOf(true) }
        val lifecycleOwner = LocalLifecycleOwner.current
        val scope = rememberCoroutineScope()

        DisposableEffect(lifecycleOwner) {
            val observer = LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_STOP -> {
                        // Only re-lock the UI and purge keys if the user's policy says so.
                        if (!isChangingConfigurations && masterPasswordManager.shouldLockOnExit(applicationContext)) {
                            isLocked = true
                            masterPasswordManager.lockVault()
                            viewModel.lockVault()
                        }
                        onRefreshVault()
                    }
                    Lifecycle.Event.ON_RESUME -> {
                        // Security Hardening: Active Revocation Check
                        scope.launch {
                            val uid = authenticator.uid ?: "guest"
                            if (masterPasswordManager.isUnlocked() && deviceTrustManager.isCurrentDeviceRevoked(uid)) {
                                withContext(Dispatchers.Main) {
                                    masterPasswordManager.lockVault()
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
                if (uid != "guest") {
                    try {
                        deviceTrustManager.registerCurrentDevice(uid)
                    } catch (_: Exception) {}
                    try {
                        credentialShareManager.registerMyKeysIfNeeded(applicationContext, uid)
                    } catch (_: Exception) {}
                }
            }
            ZeroKeyApp(viewModel, syncViewModel, uid, masterPasswordManager, biometricVaultUnlockManager, onRefreshVault)
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        masterPasswordManager.onTrimMemory(level)
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
        Box(modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface), contentAlignment = Alignment.Center) {
            val remaining = authManager.getRemainingLockoutTime() / 1000
            Text("Too many attempts. Please try again in $remaining seconds.", textAlign = TextAlign.Center)
        }
        return
    }

    // Bump this to (re)launch the system prompt: once automatically, again on button tap.
    var promptTrigger by remember { mutableStateOf(0) }

    Box(
        modifier = Modifier.fillMaxSize().background(MaterialTheme.colorScheme.surface),
        contentAlignment = Alignment.Center
    ) {
        Column(horizontalAlignment = Alignment.CenterHorizontally) {
            Icon(Icons.Default.Lock, contentDescription = null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.primary)
            Spacer(modifier = Modifier.height(24.dp))
            Button(onClick = { promptTrigger++ }) {
                Text("Unlock ZeroKey")
            }
        }
    }

    val executor = remember { ContextCompat.getMainExecutor(context) }
    val biometricPrompt = remember {
        BiometricPrompt(context, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                authManager.resetAttempts()
                onAuthenticated()
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                if (errorCode != BiometricPrompt.ERROR_USER_CANCELED && errorCode != BiometricPrompt.ERROR_NEGATIVE_BUTTON) {
                    authManager.recordFailedAttempt()
                    Toast.makeText(context, "Authentication error: $errString", Toast.LENGTH_SHORT).show()
                }
            }
        })
    }

    val promptInfo = remember {
        val builder = BiometricPrompt.PromptInfo.Builder()
            .setTitle("ZeroKey Unlock")
            .setSubtitle("Authenticate to access your vault")
        // BIOMETRIC_STRONG + DEVICE_CREDENTIAL is only allowed on API 30+.
        if (android.os.Build.VERSION.SDK_INT >= 30) {
            builder.setAllowedAuthenticators(
                androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
                androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
            )
        } else {
            builder.setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
            builder.setNegativeButtonText("Cancel")
        }
        builder.build()
    }

    // Auto-prompt on first entry (promptTrigger starts at 0), and again whenever it changes.
    LaunchedEffect(promptTrigger) {
        biometricPrompt.authenticate(promptInfo)
    }
}

@Composable
fun ZeroKeyApp(
    viewModel: PasswordViewModel, 
    syncViewModel: SyncViewModel,
    userId: String,
    masterPasswordManager: MasterPasswordManager,
    biometricUnlockManager: com.hariharan.zerokey.security.BiometricVaultUnlockManager,
    onSignOut: () -> Unit
) {
    val navController = rememberNavController()
    var generatedPasswordToUse by remember { mutableStateOf<String?>(null) }
    
    val context = LocalContext.current
    var backPressedTime by remember { mutableStateOf(0L) }

    // Custom BackHandler for main app navigation
    BackHandler {
        if (navController.previousBackStackEntry != null) {
            navController.popBackStack()
            backPressedTime = 0L
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

    NavHost(navController = navController, startDestination = Screen.Vault.route) {
        composable(Screen.Vault.route) {
            VaultScreen(
                viewModel = viewModel,
                onAddClick = { navController.navigate(Screen.AddPassword.route) },
                onSecurityActivityClick = { navController.navigate(Screen.SecurityActivity.route) },
                onPasswordHealthClick = { navController.navigate(Screen.PasswordHealth.route) },
                onSecurityDashboardClick = { navController.navigate(Screen.SecurityDashboard.route) },
                onSharingClick = { navController.navigate(Screen.CredentialSharing.route) },
                onSyncClick = { navController.navigate(Screen.CloudSync.route) },
                onSettingsClick = { navController.navigate(Screen.Settings.route) }
            )
        }
        composable(Screen.AddPassword.route) {
            AddPasswordScreen(
                viewModel = viewModel,
                initialPassword = generatedPasswordToUse ?: "",
                onBack = { 
                    navController.popBackStack()
                    generatedPasswordToUse = null
                },
                onGenerateClick = { navController.navigate(Screen.Generator.route) }
            )
        }
        composable(Screen.SecurityActivity.route) {
            SecurityActivityScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() }
            )
        }
        composable(Screen.PasswordHealth.route) {
            PasswordHealthScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() }
            )
        }
        composable(Screen.Generator.route) {
            PasswordGeneratorScreen(
                onBack = { navController.popBackStack() },
                onUsePassword = { 
                    generatedPasswordToUse = it
                    navController.popBackStack()
                }
            )
        }
        composable(Screen.SecurityDashboard.route) {
            SecurityDashboardScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() },
                onFixCredential = { id ->
                    navController.navigate(Screen.PasswordDetail.createRoute(id))
                }
            )
        }
        composable(
            route = Screen.PasswordDetail.route,
            arguments = listOf(navArgument("id") { type = NavType.IntType })
        ) { backStackEntry ->
            val id = backStackEntry.arguments?.getInt("id")
            if (id != null) {
                PasswordDetailScreen(
                    itemId = id,
                    viewModel = viewModel,
                    onBack = { navController.popBackStack() },
                    onDeleted = { navController.popBackStack() }
                )
            }
        }
        composable(Screen.CredentialSharing.route) {
            CredentialSharingScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() },
                userId = userId
            )
        }
        composable(Screen.CloudSync.route) {
            SyncScreen(
                viewModel = syncViewModel,
                onBack = { navController.popBackStack() },
                userId = userId
            )
        }
        composable(Screen.Settings.route) {
            SettingsScreen(
                viewModel = viewModel,
                masterPasswordManager = masterPasswordManager,
                biometricUnlockManager = biometricUnlockManager,
                onBack = { navController.popBackStack() },
                onManageDevices = { navController.navigate(Screen.DeviceManagement.route) },
                onSignOut = onSignOut
            )
        }
        composable(Screen.DeviceManagement.route) {
            DeviceManagementScreen(
                viewModel = viewModel,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
