package com.hariharan.zerokey.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hariharan.zerokey.R
import com.hariharan.zerokey.security.FirebaseAuthenticator
import com.hariharan.zerokey.core.security.MasterPasswordManager
import com.hariharan.zerokey.core.common.PrivacyLogger
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

@Composable
fun AuthScreen(
    authenticator: FirebaseAuthenticator,
    masterPasswordManager: MasterPasswordManager,
    authAttemptManager: com.hariharan.zerokey.core.security.AuthAttemptManager,
    biometricUnlockManager: com.hariharan.zerokey.security.BiometricVaultUnlockManager,
    onAuthSuccess: () -> Unit,
    onSignOut: () -> Unit = {}
) {
    val currentUser by authenticator.userState.collectAsState()
    val isFirebaseAuthenticated = currentUser != null

    var isLogin by remember { mutableStateOf(true) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    var errorCount by remember { mutableStateOf(0) }
    
    var isRestoringSession by remember { mutableStateOf(false) }
    var isSetupRequired by remember { mutableStateOf(false) }
    var hasRemoteVault by remember { mutableStateOf(false) }
    var remoteVaultBlob by remember { mutableStateOf<com.hariharan.zerokey.sync.EncryptedVaultBlob?>(null) }
    
    var showRecovery by remember { mutableStateOf(false) }
    val canBiometric = remember { biometricUnlockManager.isEnrolled() && biometricUnlockManager.isSupported() }
    var useBiometric by remember { mutableStateOf(false) }
    var biometricTried by remember { mutableStateOf(false) }
    
    // Lockout state
    var lockoutSeconds by remember { mutableStateOf(0L) }

    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val webClientId = stringResource(id = R.string.default_web_client_id)

    LaunchedEffect(Unit) {
        while(true) {
            val uid = currentUser?.uid ?: email
            if (uid.isNotEmpty()) {
                val remaining = authAttemptManager.getRemainingLockoutTime(uid) / 1000
                if (remaining > 0) {
                    lockoutSeconds = remaining
                    errorMessage = "Too many attempts. Try again in ${String.format("%02d:%02d", remaining / 60, remaining % 60)}."
                } else if (lockoutSeconds > 0) {
                    lockoutSeconds = 0
                    errorMessage = "You can now enter your password."
                }
            }
            kotlinx.coroutines.delay(1000)
        }
    }

    LaunchedEffect(isFirebaseAuthenticated) {
        if (isFirebaseAuthenticated && !masterPasswordManager.isUnlocked()) {
            val uid = currentUser?.uid ?: return@LaunchedEffect
            masterPasswordManager.setUserId(uid)
            if (masterPasswordManager.isSetup(context, uid)) {
                isRestoringSession = true
                isSetupRequired = false
                if (canBiometric) useBiometric = true
            } else {
                // Check if user has a vault in the cloud
                isLoading = true
                try {
                    val doc = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                        .collection("encrypted_vault_snapshots")
                        .document(uid).get().await()
                    if (doc.exists()) {
                        remoteVaultBlob = com.hariharan.zerokey.sync.EncryptedVaultBlob.fromMap(doc.data!!)
                        hasRemoteVault = true
                        isRestoringSession = true
                        isSetupRequired = false
                    } else {
                        isRestoringSession = false
                        isSetupRequired = true
                    }
                } catch (_: Exception) {
                    isRestoringSession = false
                    isSetupRequired = true
                }
                isLoading = false
            }
        } else if (!isFirebaseAuthenticated) {
            isRestoringSession = false
            isSetupRequired = false
            hasRemoteVault = false
        }
    }

    LaunchedEffect(useBiometric) {
        if (useBiometric && !biometricTried) {
            biometricTried = true
            val activity = context as? androidx.fragment.app.FragmentActivity
            if (activity != null) {
                biometricUnlockManager.unlock(activity) { rawKey ->
                    if (rawKey != null) {
                        val uid = currentUser?.uid ?: "unknown"
                        masterPasswordManager.restoreVaultKey(rawKey, uid)
                        java.util.Arrays.fill(rawKey, 0)
                        authAttemptManager.resetAttempts(uid)
                        onAuthSuccess()
                    }
                }
            }
        }
    }

    val surfaceColor = MaterialTheme.colorScheme.surface

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        surfaceColor,
                        surfaceColor.copy(alpha = 0.95f),
                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.1f)
                    )
                )
            )
            .statusBarsPadding()
            .navigationBarsPadding()
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 32.dp)
                .verticalScroll(rememberScrollState()),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "ZeroKey",
                style = MaterialTheme.typography.displayMedium.copy(letterSpacing = (-2).sp, fontWeight = FontWeight.Black),
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center
            )
            
            Text(
                text = when {
                    isRestoringSession && useBiometric -> "Unlock with biometrics to open your vault."
                    isRestoringSession && hasRemoteVault -> "Vault found in cloud. Enter your master password to restore it to this device."
                    isRestoringSession -> "Enter your master password to unlock your vault."
                    isSetupRequired -> "One last step: Create your Master Password. This password encrypts your vault and is never sent to us."
                    else -> "The invisible vault for your digital life."
                },
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                modifier = Modifier.padding(top = 8.dp, bottom = 48.dp),
                textAlign = TextAlign.Center
            )

            // Hide Email field if already authenticated (Setup mode)
            if (!isRestoringSession && !isSetupRequired) {
                TransparentTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = "Email",
                    leadingIcon = Icons.Default.Email,
                    keyboardType = KeyboardType.Email
                )
                Spacer(modifier = Modifier.height(20.dp))
            }

            if (isRestoringSession && useBiometric) {
                Button(
                    onClick = {
                        val activity = context as? androidx.fragment.app.FragmentActivity
                        if (activity != null) {
                            biometricUnlockManager.unlock(activity) { rawKey ->
                                if (rawKey != null) {
                                    masterPasswordManager.restoreVaultKey(rawKey)
                                    java.util.Arrays.fill(rawKey, 0)
                                    val uid = currentUser?.uid ?: "unknown"
                                    authAttemptManager.resetAttempts(uid)
                                    onAuthSuccess()
                                } else {
                                    errorMessage = "Biometric unlock failed."
                                }
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(60.dp),
                    shape = RoundedCornerShape(20.dp),
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.onSurface, contentColor = MaterialTheme.colorScheme.surface)
                ) { Text("Unlock with biometrics", fontWeight = FontWeight.Bold) }
                TextButton(onClick = { useBiometric = false }, modifier = Modifier.padding(top = 8.dp)) {
                    Text("Use master password instead", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else {
                TransparentTextField(
                    value = password,
                    onValueChange = { 
                        password = it
                        if (errorMessage != null) {
                            errorMessage = null // Clear error when user starts typing again
                        }
                    },
                    label = if (isSetupRequired) "Choose Master Password" else "Master Password",
                    leadingIcon = Icons.Default.Lock,
                    keyboardType = KeyboardType.Password,
                    isPassword = true,
                    passwordVisible = passwordVisible,
                    onPasswordToggle = { passwordVisible = !passwordVisible }
                )
            }

            AnimatedVisibility(
                visible = errorMessage != null, 
                enter = fadeIn() + expandVertically() + scaleIn(initialScale = 0.9f), 
                exit = fadeOut() + shrinkVertically()
            ) {
                key(errorCount) {
                    Text(
                        text = errorMessage ?: "", 
                        color = MaterialTheme.colorScheme.error, 
                        style = MaterialTheme.typography.bodySmall.copy(fontWeight = FontWeight.Bold), 
                        modifier = Modifier
                            .padding(top = 16.dp)
                            .animateContentSize(),
                        textAlign = TextAlign.Center
                    )
                }
            }

            Spacer(modifier = Modifier.height(48.dp))

            if (!(isRestoringSession && useBiometric)) Button(
                onClick = {
                    scope.launch {
                        isLoading = true
                        errorMessage = null
                        
                        val uidForLockout = currentUser?.uid ?: email
                        if (authAttemptManager.isLockedOut(uidForLockout)) {
                            val rem = authAttemptManager.getRemainingLockoutTime(uidForLockout) / 1000
                            errorMessage = "Too many attempts. Try again in ${rem}s."
                            isLoading = false
                            return@launch
                        }

                        if (isRestoringSession || isSetupRequired) {
                            try {
                                val currentUid = currentUser?.uid ?: throw IllegalStateException("User not logged in")
                                masterPasswordManager.setUserId(currentUid)
                                
                                if (hasRemoteVault && remoteVaultBlob != null) {
                                    // RESTORE FLOW
                                    val blob = remoteVaultBlob!!
                                    if (blob.wrappedVaultKey == null || blob.wrappedVaultKeyIv == null) {
                                        throw IllegalStateException("Cloud vault is missing recovery key. Use a recovery code instead.")
                                    }
                                    
                                    PrivacyLogger.i("AuthScreen", "Restoring vault from cloud...")
                                    val wrapped = com.hariharan.zerokey.core.crypto.EncryptedData(
                                        android.util.Base64.decode(blob.wrappedVaultKey, android.util.Base64.NO_WRAP),
                                        android.util.Base64.decode(blob.wrappedVaultKeyIv, android.util.Base64.NO_WRAP)
                                    )
                                    
                                    // Set salt locally first (needed for key derivation)
                                    // (Assuming salt is available in users/uid doc or we need to fetch it)
                                    // Wait, the SyncBlob doesn't have the salt. The salt is in the users/UID doc.
                                    val userDoc = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                                        .collection("users").document(currentUid).get().await()
                                    val saltB64 = userDoc.getString("vault_salt") 
                                        ?: throw IllegalStateException("Cloud vault metadata (salt) missing.")
                                    
                                    val salt = android.util.Base64.decode(saltB64, android.util.Base64.NO_WRAP)
                                    // Manually save salt locally as masterPasswordManager expects it on disk
                                    val prefs = context.getSharedPreferences("master_password_prefs_" + android.util.Base64.encodeToString(currentUid.toByteArray(), android.util.Base64.NO_WRAP), android.content.Context.MODE_PRIVATE)
                                    // Actually masterPasswordManager has internal saveSalt but it's private.
                                    // Let's use a public way if possible or just unwrap then import.
                                    
                                    // 1. Derive master key from password
                                    val derivedKey = masterPasswordManager.deriveMasterKey(
                                        password.toCharArray(), salt, userDoc.getLong("crypto_version")?.toInt() ?: 1
                                    )
                                    
                                    // 2. Import into manager
                                    masterPasswordManager.importVaultKey(context, wrapped, derivedKey, salt)
                                    PrivacyLogger.i("AuthScreen", "Vault restored successfully.")
                                } else if (!masterPasswordManager.isSetup(context, currentUid)) {
                                    PrivacyLogger.i("AuthScreen", "Setting up new vault...")
                                    masterPasswordManager.setupVault(context, password.toCharArray(), currentUid)
                                } else {
                                    PrivacyLogger.i("AuthScreen", "Unlocking existing vault...")
                                    masterPasswordManager.unlockVault(context, password.toCharArray(), currentUid)
                                }
                                PrivacyLogger.i("AuthScreen", "Vault open. Transitioning...")
                                authAttemptManager.resetAttempts(currentUid)
                                onAuthSuccess()
                            } catch (e: Exception) {
                                val currentUid = currentUser?.uid ?: "unknown"
                                authAttemptManager.recordFailedAttempt(currentUid)
                                errorMessage = "Incorrect password. Please try again."
                                errorCount++ // Force re-animate the error text
                            }
                        } else {
                            val authResult = if (isLogin) authenticator.signIn(email, password) else authenticator.signUp(email, password)
                            when (authResult) {
                                is com.hariharan.zerokey.security.AuthResult.Success -> {
                                    // Successfully logged into Firebase, next check vault
                                    val newUid = authResult.user.uid
                                    masterPasswordManager.setUserId(newUid)
                                    if (!masterPasswordManager.isSetup(context, newUid)) {
                                        // Wait for LaunchedEffect to switch UI or handle here
                                        isSetupRequired = true
                                    } else {
                                        isRestoringSession = true
                                    }
                                }
                                is com.hariharan.zerokey.security.AuthResult.Error -> {
                                    errorMessage = authResult.message
                                    errorCount++ // Force re-animate
                                }
                            }
                        }
                        isLoading = false
                    }
                },
                modifier = Modifier.fillMaxWidth().height(64.dp), // Increased height slightly
                shape = RoundedCornerShape(20.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.onSurface, 
                    contentColor = MaterialTheme.colorScheme.surface,
                    disabledContainerColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.12f)
                ),
                elevation = ButtonDefaults.buttonElevation(
                    defaultElevation = 0.dp,
                    pressedElevation = 8.dp, // High contrast pop on click
                    hoveredElevation = 4.dp
                ),
                enabled = !isLoading && (isRestoringSession || isSetupRequired || email.isNotEmpty()) && password.length >= 6
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.surface)
                } else {
                    Text(
                        text = when {
                            isRestoringSession -> "Unlock Vault"
                            isSetupRequired -> "Set Master Password"
                            isLogin -> "Sign In"
                            else -> "Create Account"
                        }, 
                        fontWeight = FontWeight.Bold
                    )
                }
            }

            // Google Sign-In and Switch Login/Signup (only show if not in Setup/Unlock mode)
            if (!isRestoringSession && !isSetupRequired) {
                Spacer(modifier = Modifier.height(16.dp))
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            isLoading = true
                            errorMessage = null
                            try {
                                val user = authenticator.signInWithGoogle(context, webClientId)
                                if (user != null) {
                                    masterPasswordManager.setUserId(user.uid)
                                    if (masterPasswordManager.isSetup(context, user.uid)) {
                                        isRestoringSession = true
                                        isSetupRequired = false
                                    } else {
                                        isRestoringSession = false
                                        isSetupRequired = true
                                    }
                                }
                                else {
                                    errorMessage = "Google sign-in was canceled."
                                    errorCount++
                                }
                            } catch (e: Exception) { 
                                errorMessage = e.message ?: "Google sign-in failed." 
                                errorCount++
                            }
                            isLoading = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = RoundedCornerShape(20.dp),
                    elevation = ButtonDefaults.buttonElevation(pressedElevation = 8.dp),
                    enabled = !isLoading
                ) { Text("Continue with Google", fontWeight = FontWeight.Medium) }

                Spacer(modifier = Modifier.height(32.dp))
                TextButton(onClick = { isLogin = !isLogin }, modifier = Modifier.padding(bottom = 16.dp)) {
                    Text(text = if (isLogin) "New to ZeroKey? Create Account" else "Already a member? Sign In", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            } else if (!useBiometric) {
                // Secondary options for setup/unlock mode
                if (isRestoringSession) {
                    if (showRecovery) {
                        var recCode by remember { mutableStateOf("") }
                        var recNewPass by remember { mutableStateOf("") }
                        var recError by remember { mutableStateOf<String?>(null) }
                        var recErrorCount by remember { mutableStateOf(0) }
                        var recLoading by remember { mutableStateOf(false) }
                        AlertDialog(
                            onDismissRequest = { showRecovery = false },
                            title = { Text("Reset with Recovery Key") },
                            text = {
                                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                    Text("Enter recovery code and choose a new master password.", style = MaterialTheme.typography.bodySmall)
                                    OutlinedTextField(value = recCode, onValueChange = { recCode = it; recError = null }, label = { Text("Recovery Code") }, modifier = Modifier.fillMaxWidth())
                                    OutlinedTextField(value = recNewPass, onValueChange = { recNewPass = it; recError = null }, label = { Text("New Master Password") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                                    
                                    AnimatedVisibility(visible = recError != null, enter = fadeIn() + expandVertically()) {
                                        key(recErrorCount) {
                                            Text(recError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall.copy(fontWeight = FontWeight.Bold))
                                        }
                                    }
                                }
                            },
                            confirmButton = {
                                Button(
                                    enabled = !recLoading && recNewPass.length >= 6 && (recCode.length == 32 || recCode.length == 64), 
                                    elevation = ButtonDefaults.buttonElevation(pressedElevation = 8.dp),
                                    onClick = {
                                        scope.launch {
                                            recLoading = true; recError = null
                                            try {
                                                val blobs = mutableListOf<MasterPasswordManager.RecoveryBlob>()
                                                val uid = currentUser?.uid
                                                if (uid != null) {
                                                    try {
                                                        val doc = com.google.firebase.firestore.FirebaseFirestore.getInstance().collection("users").document(uid).get().await()
                                                        (doc.get("recoveryBlobs") as? List<*>)?.forEach { item ->
                                                            val map = item as? Map<*, *>
                                                            val b = map?.get("blob") as? String
                                                            val i = map?.get("iv") as? String
                                                            val f = map?.get("vaultKeyFingerprint") as? String
                                                            if (b != null && i != null) blobs.add(MasterPasswordManager.RecoveryBlob(b, i, f ?: ""))
                                                        }
                                                    } catch (_: Exception) {}
                                                }
                                                if (blobs.isEmpty()) blobs.addAll(masterPasswordManager.getLocalRecoveryBlobs(context))
                                                if (blobs.isEmpty()) {
                                                    recError = "No recovery keys found."
                                                    recErrorCount++
                                                }
                                                else { 
                                                    uid?.let { masterPasswordManager.setUserId(it) }
                                                    masterPasswordManager.recoverWithRecoveryCode(context, blobs, recCode, recNewPass.toCharArray())
                                                    showRecovery = false
                                                    onAuthSuccess() 
                                                }
                                            } catch (e: Exception) { 
                                                recError = e.message ?: "Invalid code." 
                                                recErrorCount++
                                            }
                                            recLoading = false
                                        }
                                    }
                                ) { Text("Reset Password") }
                            },
                            dismissButton = { TextButton(onClick = { showRecovery = false }) { Text("Cancel") } }
                        )
                    }
                    TextButton(onClick = { showRecovery = true }, modifier = Modifier.padding(top = 4.dp)) { Text("Forgot master password?", color = MaterialTheme.colorScheme.primary) }
                }

                TextButton(onClick = { 
                    onSignOut()
                    isRestoringSession = false 
                    isSetupRequired = false
                    email = ""
                    password = ""
                }) { Text("Sign in with a different account", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
        }
    }
}

@Composable
fun TransparentTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    leadingIcon: androidx.compose.ui.graphics.vector.ImageVector,
    keyboardType: KeyboardType = KeyboardType.Text,
    isPassword: Boolean = false,
    passwordVisible: Boolean = false,
    onPasswordToggle: () -> Unit = {}
) {
    TextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = Modifier.fillMaxWidth(),
        leadingIcon = { Icon(leadingIcon, contentDescription = null, modifier = Modifier.size(20.dp)) },
        trailingIcon = if (isPassword) {
            {
                IconButton(onClick = onPasswordToggle) {
                    Icon(
                        imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                        contentDescription = null,
                        modifier = Modifier.size(20.dp)
                    )
                }
            }
        } else null,
        visualTransformation = if (isPassword && !passwordVisible) PasswordVisualTransformation() else VisualTransformation.None,
        keyboardOptions = KeyboardOptions(keyboardType = keyboardType),
        singleLine = true,
        colors = TextFieldDefaults.colors(
            focusedContainerColor = Color.Transparent,
            unfocusedContainerColor = Color.Transparent,
            disabledContainerColor = Color.Transparent,
            focusedIndicatorColor = MaterialTheme.colorScheme.onSurface,
            unfocusedIndicatorColor = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f),
            focusedLabelColor = MaterialTheme.colorScheme.onSurface,
            unfocusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
        )
    )
}
