package com.hariharan.zerokey.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
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
    var isLogin by remember { mutableStateOf(true) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    
    var isRestoringSession by remember { mutableStateOf(false) }
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
            val remaining = authAttemptManager.getRemainingLockoutTime() / 1000
            if (remaining > 0) {
                lockoutSeconds = remaining
                errorMessage = "Too many attempts. Try again in ${String.format("%02d:%02d", remaining / 60, remaining % 60)}."
            } else if (lockoutSeconds > 0) {
                lockoutSeconds = 0
                errorMessage = "You can now enter your password."
            }
            kotlinx.coroutines.delay(1000)
        }
    }

    LaunchedEffect(authenticator.isAuthenticated) {
        if (authenticator.isAuthenticated && !masterPasswordManager.isUnlocked()) {
            isRestoringSession = true
            if (canBiometric && masterPasswordManager.isSetup(context)) useBiometric = true
        }
    }

    LaunchedEffect(useBiometric) {
        if (useBiometric && !biometricTried) {
            biometricTried = true
            val activity = context as? androidx.fragment.app.FragmentActivity
            if (activity != null) {
                biometricUnlockManager.unlock(activity) { rawKey ->
                    if (rawKey != null) {
                        masterPasswordManager.restoreVaultKey(rawKey)
                        java.util.Arrays.fill(rawKey, 0)
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
                text = if (isRestoringSession && useBiometric) "Unlock with biometrics to open your vault."
                       else if (isRestoringSession) "Enter your master password to unlock your vault."
                       else "The invisible vault for your digital life.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                modifier = Modifier.padding(top = 8.dp, bottom = 48.dp),
                textAlign = TextAlign.Center
            )

            if (!isRestoringSession) {
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
                    onValueChange = { password = it },
                    label = "Master Password",
                    leadingIcon = Icons.Default.Lock,
                    keyboardType = KeyboardType.Password,
                    isPassword = true,
                    passwordVisible = passwordVisible,
                    onPasswordToggle = { passwordVisible = !passwordVisible }
                )
            }

            AnimatedVisibility(visible = errorMessage != null, enter = fadeIn(), exit = fadeOut()) {
                Text(text = errorMessage ?: "", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(top = 12.dp), textAlign = TextAlign.Center)
            }

            Spacer(modifier = Modifier.height(48.dp))

            if (!(isRestoringSession && useBiometric)) Button(
                onClick = {
                    scope.launch {
                        isLoading = true
                        errorMessage = null
                        
                        if (authAttemptManager.isLockedOut()) {
                            val rem = authAttemptManager.getRemainingLockoutTime() / 1000
                            errorMessage = "Too many attempts. Try again in ${rem}s."
                            isLoading = false
                            return@launch
                        }

                        if (isRestoringSession) {
                            try {
                                if (!masterPasswordManager.isSetup(context)) {
                                    masterPasswordManager.setupVault(context, password.toCharArray())
                                } else {
                                    masterPasswordManager.unlockVault(context, password.toCharArray())
                                }
                                authAttemptManager.resetAttempts()
                                onAuthSuccess()
                            } catch (e: Exception) {
                                authAttemptManager.recordFailedAttempt(authenticator.currentUser?.email ?: "unknown")
                                errorMessage = "Vault unlock failed: Incorrect password"
                            }
                        } else {
                            val authResult = if (isLogin) authenticator.signIn(email, password) else authenticator.signUp(email, password)
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
                                        authAttemptManager.recordFailedAttempt(email)
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
                modifier = Modifier.fillMaxWidth().height(60.dp),
                shape = RoundedCornerShape(20.dp),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.onSurface, contentColor = MaterialTheme.colorScheme.surface),
                enabled = !isLoading && (isRestoringSession || email.isNotEmpty()) && password.length >= 6
            ) {
                if (isLoading) {
                    CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp, color = MaterialTheme.colorScheme.surface)
                } else {
                    Text(text = if (isRestoringSession) "Unlock Vault" else if (isLogin) "Sign In" else "Create Account", fontWeight = FontWeight.Bold)
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
                                val user = authenticator.signInWithGoogle(context, webClientId)
                                if (user != null) isRestoringSession = true
                                else errorMessage = "Google sign-in was canceled."
                            } catch (e: Exception) { errorMessage = e.message ?: "Google sign-in failed." }
                            isLoading = false
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = RoundedCornerShape(20.dp),
                    enabled = !isLoading
                ) { Text("Continue with Google", fontWeight = FontWeight.Medium) }
            } else if (!useBiometric) {
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
                                Text("Enter recovery code and choose a new master password.", style = MaterialTheme.typography.bodySmall)
                                OutlinedTextField(value = recCode, onValueChange = { recCode = it }, label = { Text("Recovery Code") }, modifier = Modifier.fillMaxWidth())
                                OutlinedTextField(value = recNewPass, onValueChange = { recNewPass = it }, label = { Text("New Master Password") }, visualTransformation = PasswordVisualTransformation(), modifier = Modifier.fillMaxWidth())
                                if (recError != null) Text(recError!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                            }
                        },
                        confirmButton = {
                            Button(enabled = !recLoading && recNewPass.length >= 6 && (recCode.length == 32 || recCode.length == 64), onClick = {
                                scope.launch {
                                    recLoading = true; recError = null
                                    try {
                                        val blobs = mutableListOf<MasterPasswordManager.RecoveryBlob>()
                                        val uid = com.google.firebase.auth.FirebaseAuth.getInstance().currentUser?.uid
                                        if (uid != null) {
                                            try {
                                                val doc = com.google.firebase.firestore.FirebaseFirestore.getInstance().collection("users").document(uid).get().await()
                                                (doc.get("recoveryBlobs") as? List<*>)?.forEach { item ->
                                                    val map = item as? Map<*, *>
                                                    val b = map?.get("blob") as? String
                                                    val i = map?.get("iv") as? String
                                                    if (b != null && i != null) blobs.add(MasterPasswordManager.RecoveryBlob(b, i))
                                                }
                                            } catch (_: Exception) {}
                                        }
                                        if (blobs.isEmpty()) blobs.addAll(masterPasswordManager.getLocalRecoveryBlobs(context))
                                        if (blobs.isEmpty()) recError = "No recovery keys found."
                                        else { masterPasswordManager.recoverWithRecoveryCode(context, blobs, recCode, recNewPass.toCharArray()); showRecovery = false; onAuthSuccess() }
                                    } catch (e: Exception) { recError = "Invalid code." }
                                    recLoading = false
                                }
                            }) { Text("Reset Password") }
                        },
                        dismissButton = { TextButton(onClick = { showRecovery = false }) { Text("Cancel") } }
                    )
                }
                TextButton(onClick = { showRecovery = true }, modifier = Modifier.padding(top = 4.dp)) { Text("Forgot master password?", color = MaterialTheme.colorScheme.primary) }
                TextButton(onClick = { 
                    onSignOut()
                    isRestoringSession = false 
                    email = ""
                    password = ""
                }) { Text("Sign in with a different account", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }

            if (!isRestoringSession) {
                Spacer(modifier = Modifier.height(32.dp))
                TextButton(onClick = { isLogin = !isLogin }, modifier = Modifier.padding(bottom = 16.dp)) {
                    Text(text = if (isLogin) "New to ZeroKey? Create Account" else "Already a member? Sign In", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
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
