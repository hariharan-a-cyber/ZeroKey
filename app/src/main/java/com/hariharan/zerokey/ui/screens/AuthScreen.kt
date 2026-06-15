package com.hariharan.zerokey.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Email
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
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
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await

@Composable
fun AuthScreen(
    authenticator: FirebaseAuthenticator,
    masterPasswordManager: MasterPasswordManager,
    authAttemptManager: com.hariharan.zerokey.core.security.AuthAttemptManager,
    biometricUnlockManager: com.hariharan.zerokey.security.BiometricVaultUnlockManager,
    onAuthSuccess: () -> Unit
) {
    var isLogin by remember { mutableStateOf(true) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    
    // For Session Restoration: if user is logged in via Google but vault is locked, 
    // we show a "Restore Session" state to get the Master Password.
    var isRestoringSession by remember { mutableStateOf(false) }
    var showRecovery by remember { mutableStateOf(false) }
    
    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val webClientId = stringResource(id = R.string.default_web_client_id)

    // Check if we need to restore vault session
    LaunchedEffect(authenticator.isAuthenticated) {
        if (authenticator.isAuthenticated && !masterPasswordManager.isUnlocked()) {
            isRestoringSession = true
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
            // Premium Branding
            Text(
                text = "ZeroKey",
                style = MaterialTheme.typography.displayMedium.copy(
                    letterSpacing = (-2).sp,
                    fontWeight = FontWeight.Black
                ),
                color = MaterialTheme.colorScheme.onSurface,
                textAlign = TextAlign.Center
            )
            
            Text(
                text = if (isRestoringSession) "Enter your master password to unlock your vault." else "The invisible vault for your digital life.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                modifier = Modifier.padding(top = 8.dp, bottom = 48.dp),
                textAlign = TextAlign.Center
            )

            if (!isRestoringSession) {
                // Minimalist Form
                TransparentTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = "Email",
                    leadingIcon = Icons.Default.Email,
                    keyboardType = KeyboardType.Email
                )

                Spacer(modifier = Modifier.height(20.dp))
            }

            TransparentTextField(
                value = password,
                onValueChange = { password = it },
                label = "Master Password",
                leadingIcon = Icons.Default.Lock,
                keyboardType = KeyboardType.Password,
                isPassword = true,
                passwordVisible = passwordVisible,
                onPasswordToggle = { passwordVisible = !passwordVisible }
            )

            AnimatedVisibility(
                visible = errorMessage != null,
                enter = fadeIn(),
                exit = fadeOut()
            ) {
                Text(
                    text = errorMessage ?: "",
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 12.dp),
                    textAlign = TextAlign.Center
                )
            }

            Spacer(modifier = Modifier.height(48.dp))

            // Premium Primary Action
            Button(
                onClick = {
                    scope.launch {
                        isLoading = true
                        errorMessage = null
                        
                        if (authAttemptManager.isLockedOut()) {
                            val secs = authAttemptManager.getRemainingLockoutTime() / 1000
                            errorMessage = "Too many attempts. Try again in ${secs}s."
                            isLoading = false
                            return@launch
                        }

                        if (isRestoringSession) {
                            try {
                                if (!masterPasswordManager.isSetup(context)) {
                                    // First-time Google user: create the vault with this master password.
                                    masterPasswordManager.setupVault(context, password.toCharArray())
                                } else {
                                    masterPasswordManager.unlockVault(context, password.toCharArray())
                                }
                                authAttemptManager.resetAttempts()
                                onAuthSuccess()
                            } catch (e: Exception) {
                                authAttemptManager.recordFailedAttempt()
                                errorMessage = "Vault unlock failed: Incorrect password"
                            }
                        } else {
                            val authResult = if (isLogin) {
                                authenticator.signIn(email, password)
                            } else {
                                authenticator.signUp(email, password)
                            }
                            
                            when (authResult) {
                                is com.hariharan.zerokey.security.AuthResult.Success -> {
                                    try {
                                        if (!masterPasswordManager.isSetup(context)) {
                                            masterPasswordManager.setupVault(context, password.toCharArray())
                                        } else {
                                            masterPasswordManager.unlockVault(context, password.toCharArray())
                                        }
                                        authAttemptManager.resetAttempts()
                                        onAuthSuccess()
                                    } catch (e: Exception) {
                                        authAttemptManager.recordFailedAttempt()
                                        errorMessage = "Vault unlock failed: Incorrect password"
                                    }
                                }
                                is com.hariharan.zerokey.security.AuthResult.Error -> {
                                    errorMessage = authResult.message
                                }
                            }
                        }
                        isLoading = false
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(60.dp),
                shape = RoundedCornerShape(20.dp),
                colors = ButtonDefaults.buttonColors(
                    containerColor = MaterialTheme.colorScheme.onSurface,
                    contentColor = MaterialTheme.colorScheme.surface
                ),
                enabled = !isLoading && (isRestoringSession || email.isNotEmpty()) && password.length >= 6
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.surface
                    )
                } else {
                    Text(
                        text = if (isRestoringSession) "Unlock Vault" else if (isLogin) "Sign In" else "Create Account",
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.5.sp
                    )
                }
            }

            if (!isRestoringSession) {
                Spacer(modifier = Modifier.height(16.dp))
                OutlinedButton(
                    onClick = {
                        scope.launch {
                            isLoading = true
                            errorMessage = null
                            try {
                                if (webClientId.isEmpty() || webClientId.contains("apps.googleusercontent.com").not()) {
                                    errorMessage = "Configuration Error: Web Client ID is missing or invalid in strings.xml"
                                    isLoading = false
                                    return@launch
                                }
                                val user = authenticator.signInWithGoogle(context, webClientId)
                                if (user != null) {
                                    // Zero-knowledge: the vault key still comes from the master password,
                                    // so after Google sign-in we collect/create the master password next.
                                    isRestoringSession = true
                                } else {
                                    errorMessage = "Google sign-in was canceled."
                                }
                            } catch (e: Exception) {
                                errorMessage = e.message ?: "Google sign-in failed."
                            }
                            isLoading = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = RoundedCornerShape(20.dp),
                    border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f)),
                    enabled = !isLoading
                ) {
                    Text("Continue with Google", fontWeight = FontWeight.Medium)
                }
            } else {
                if (biometricUnlockManager.isEnrolled() && biometricUnlockManager.isSupported()) {
                    Spacer(modifier = Modifier.height(16.dp))
                    OutlinedButton(
                        onClick = {
                            val activity = context as? androidx.fragment.app.FragmentActivity
                            if (activity != null) {
                                biometricUnlockManager.unlock(activity) { rawKey ->
                                    if (rawKey != null) {
                                        masterPasswordManager.restoreVaultKey(rawKey)
                                        java.util.Arrays.fill(rawKey, 0)
                                        onAuthSuccess()
                                    } else {
                                        errorMessage = "Biometric unlock failed. Use your master password."
                                    }
                                }
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                        shape = RoundedCornerShape(20.dp),
                        border = BorderStroke(1.dp, MaterialTheme.colorScheme.outline.copy(alpha = 0.4f))
                    ) {
                        Text("Unlock with biometrics", fontWeight = FontWeight.Medium)
                    }
                }
                if (showRecovery) {
                    var recCode by remember { mutableStateOf("") }
                    var recNewPass by remember { mutableStateOf("") }
                    var recError by remember { mutableStateOf<String?>(null) }
                    var recLoading by remember { mutableStateOf(false) }
                    AlertDialog(
                        onDismissRequest = { showRecovery = false },
                        title = { Text("Reset with Recovery Key") },
                        text = {
                            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                                Text("Enter ONE of the 32-character recovery codes you saved, and choose a new master password. Your data is preserved.", style = MaterialTheme.typography.bodySmall)
                                OutlinedTextField(value = recCode, onValueChange = { recCode = it }, label = { Text("32-Character Recovery Code") }, modifier = Modifier.fillMaxWidth())
                                OutlinedTextField(value = recNewPass, onValueChange = { recNewPass = it }, label = { Text("New Master Password") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                                if (recError != null) Text(recError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                            }
                        },
                        confirmButton = {
                            Button(enabled = !recLoading && recNewPass.length >= 6 && (recCode.length == 32 || recCode.length == 64), onClick = {
                                scope.launch {
                                    recLoading = true; recError = null
                                    try {
                                        val uid = com.google.firebase.auth.FirebaseAuth.getInstance().currentUser?.uid
                                        val blobs = mutableListOf<MasterPasswordManager.RecoveryBlob>()
                                        
                                        if (uid != null) {
                                            try {
                                                val doc = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                                                    .collection("users").document(uid).get().await()
                                                
                                                val remoteBlobs = doc.get("recoveryBlobs") as? List<Map<String, String>>
                                                remoteBlobs?.forEach {
                                                    blobs.add(MasterPasswordManager.RecoveryBlob(it["blob"]!!, it["iv"]!!))
                                                }
                                            } catch (_: Exception) {}
                                        }

                                        if (blobs.isEmpty()) {
                                            val local = masterPasswordManager.getLocalRecoveryBlobs(context)
                                            blobs.addAll(local)
                                        }

                                        if (blobs.isEmpty()) {
                                            recError = "No recovery keys found for this account."
                                        } else {
                                            masterPasswordManager.recoverWithRecoveryCode(context, blobs, recCode, recNewPass.toCharArray())
                                            showRecovery = false
                                            onAuthSuccess()
                                        }
                                    } catch (e: Exception) {
                                        recError = "Invalid recovery code."
                                    }
                                    recLoading = false
                                }
                            }) { Text("Reset Password") }
                        },
                        dismissButton = { TextButton(onClick = { showRecovery = false }) { Text("Cancel") } }
                    )
                }
                TextButton(
                    onClick = { showRecovery = true },
                    modifier = Modifier.padding(top = 4.dp)
                ) {
                    Text("Forgot master password?", color = MaterialTheme.colorScheme.primary)
                }
                TextButton(
                    onClick = { 
                        scope.launch {
                            biometricUnlockManager.clear() // don't carry biometric unlock to another account
                            authenticator.signOut(context)
                            isRestoringSession = false
                        }
                    },
                    modifier = Modifier.padding(top = 16.dp)
                ) {
                    Text("Sign in with a different account", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }

            if (!isRestoringSession) {
                Spacer(modifier = Modifier.height(32.dp))

                // Switch Mode Toggle
                TextButton(
                    onClick = { isLogin = !isLogin },
                    modifier = Modifier.padding(bottom = 16.dp)
                ) {
                    Text(
                        text = if (isLogin) "New to ZeroKey? Create Account" else "Already a member? Sign In",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        textAlign = TextAlign.Center
                    )
                }
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
