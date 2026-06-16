package com.hariharan.zerokey.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.foundation.BorderStroke
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
import io.ktor.client.*
import io.ktor.client.request.*
import io.ktor.client.engine.android.*
import io.ktor.http.*
import kotlinx.serialization.json.*

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
    
    // Security/Lockout states
    var lockoutSeconds by remember { mutableStateOf(0L) }
    var isHardLocked by remember { mutableStateOf(false) }
    var otpSent by remember { mutableStateOf(false) }
    var otpInput by remember { mutableStateOf("") }
    var showCaptchaChallenge by remember { mutableStateOf(false) }
    var captchaVerified by remember { mutableStateOf(false) }

    val scope = rememberCoroutineScope()
    val context = LocalContext.current
    val webClientId = stringResource(id = R.string.default_web_client_id)

    LaunchedEffect(Unit) {
        while(true) {
            val remaining = authAttemptManager.getRemainingLockoutTime() / 1000
            val hardLocked = authAttemptManager.isHardLocked() && remaining > 0
            isHardLocked = hardLocked

            if (remaining > 0) {
                lockoutSeconds = remaining
                errorMessage = if (hardLocked) {
                    "Account Temporarily Locked. Too many failed login attempts detected."
                } else {
                    "Too many attempts. Try again in ${lockoutSeconds}s."
                }
            } else if (lockoutSeconds > 0) {
                lockoutSeconds = 0
                isHardLocked = false
                otpSent = false
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

    // --- ENHANCED CAPTCHA CHALLENGE ---
    if (showCaptchaChallenge) {
        var selectedIcons by remember { mutableStateOf(setOf<Int>()) }
        val targetIcon = remember { (0..3).random() }
        val icons = listOf(Icons.Default.Lock, Icons.Default.Shield, Icons.Default.Key, Icons.Default.Security)
        
        AlertDialog(
            onDismissRequest = { showCaptchaChallenge = false },
            title = { Text("Security Challenge") },
            text = {
                Column {
                    Text("Select all icons that represent security items to continue.")
                    Spacer(Modifier.height(16.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceEvenly
                    ) {
                        icons.forEachIndexed { index, icon ->
                            Box(
                                modifier = Modifier
                                    .size(60.dp)
                                    .background(
                                        if (selectedIcons.contains(index)) MaterialTheme.colorScheme.primaryContainer 
                                        else MaterialTheme.colorScheme.surfaceVariant,
                                        RoundedCornerShape(8.dp)
                                    )
                                    .clickable {
                                        selectedIcons = if (selectedIcons.contains(index)) selectedIcons - index else selectedIcons + index
                                    },
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(icon, null, tint = if (selectedIcons.contains(index)) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    enabled = selectedIcons.isNotEmpty(),
                    onClick = { 
                        captchaVerified = true
                        showCaptchaChallenge = false 
                    }
                ) { Text("Verify") }
            },
            dismissButton = {
                TextButton(onClick = { showCaptchaChallenge = false }) { Text("Cancel") }
            }
        )
    }

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
        if (isHardLocked) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 32.dp)
                    .verticalScroll(rememberScrollState()),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center
            ) {
                Icon(Icons.Default.Lock, null, modifier = Modifier.size(64.dp), tint = MaterialTheme.colorScheme.error)
                Spacer(Modifier.height(16.dp))
                Text("Account Temporarily Locked", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
                Text("Too many failed login attempts detected", textAlign = TextAlign.Center, color = MaterialTheme.colorScheme.onSurfaceVariant)
                
                Spacer(Modifier.height(32.dp))
                Text("Try again in: ${String.format("%02d:%02d", lockoutSeconds / 60, lockoutSeconds % 60)}", style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold)

                Spacer(Modifier.height(48.dp))

                if (!otpSent) {
                    Button(
                        onClick = { 
                            scope.launch {
                                isLoading = true
                                try {
                                    val uid = authenticator.currentUser?.uid ?: return@launch
                                    val userEmail = authenticator.currentUser?.email ?: return@launch
                                    val generatedOtp = (100000..999999).random().toString()
                                    val expiry = System.currentTimeMillis() + (10 * 60 * 1000)
                                    
                                    val db = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                                    db.collection("users").document(uid)
                                        .collection("security").document("lockout_status")
                                        .set(mapOf(
                                            "currentOtp" to generatedOtp,
                                            "otpExpiresAt" to expiry,
                                            "requestedAt" to com.google.firebase.firestore.FieldValue.serverTimestamp()
                                        ), com.google.firebase.firestore.SetOptions.merge())
                                        .await()

                                    val scriptUrl = "https://script.google.com/macros/s/AKfycbws8rlCUlp6T5eyPSD8UB2W_MqILSQV94Pa5tGCcA8Cz-ES9jgh9hJcMyiWCFSr4S8B/exec"
                                    val client = HttpClient(Android)
                                    val response = client.post(scriptUrl) {
                                        contentType(ContentType.Application.Json)
                                        setBody(buildJsonObject {
                                            put("secret", "ZeroKey_Secret_99")
                                            put("to", userEmail)
                                            put("subject", "Verification code for ZeroKey")
                                            put("body", "Hello,\n\nYour requested verification code is: $generatedOtp\n\nFor your security, this code will expire in 10 minutes. If you did not request this code, you can safely ignore this email.")
                                        }.toString())
                                    }
                                    client.close()

                                    if (response.status.value in 200..299) {
                                        otpSent = true
                                        errorMessage = null
                                    } else { errorMessage = "Email failed. Try again." }
                                } catch (e: Exception) { errorMessage = "Error: ${e.message}" }
                                isLoading = false
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                        shape = RoundedCornerShape(20.dp),
                        enabled = !isLoading
                    ) { 
                        if (isLoading) CircularProgressIndicator(modifier = Modifier.size(24.dp), color = MaterialTheme.colorScheme.onPrimary)
                        else Text("Send OTP to registered email") 
                    }
                } else {
                    Text("OTP sent! Please check your email (including spam).", color = MaterialTheme.colorScheme.primary, fontWeight = FontWeight.Bold, textAlign = TextAlign.Center)
                    Spacer(Modifier.height(16.dp))
                    TransparentTextField(
                        value = otpInput,
                        onValueChange = { otpInput = it },
                        label = "Enter 6-digit OTP",
                        leadingIcon = Icons.Default.Email,
                        keyboardType = KeyboardType.NumberPassword
                    )
                    Spacer(Modifier.height(24.dp))
                    Button(
                        onClick = {
                            scope.launch {
                                isLoading = true
                                try {
                                    val uid = authenticator.currentUser?.uid ?: return@launch
                                    val db = com.google.firebase.firestore.FirebaseFirestore.getInstance()
                                    val doc = db.collection("users").document(uid).collection("security").document("lockout_status").get().await()
                                    
                                    if (otpInput == doc.getString("currentOtp") && System.currentTimeMillis() <= (doc.getLong("otpExpiresAt") ?: 0L)) {
                                        authAttemptManager.resetAttempts()
                                        isHardLocked = false
                                        otpSent = false
                                        otpInput = ""
                                        errorMessage = "Vault unlocked. Please sign in."
                                    } else { errorMessage = "Invalid or expired OTP." }
                                } catch (e: Exception) { errorMessage = "Verification failed." }
                                isLoading = false
                            }
                        },
                        modifier = Modifier.fillMaxWidth().height(56.dp),
                        shape = RoundedCornerShape(20.dp),
                        enabled = otpInput.length == 6 && !isLoading
                    ) { 
                        if (isLoading) CircularProgressIndicator(modifier = Modifier.size(24.dp), color = MaterialTheme.colorScheme.onPrimary)
                        else Text("Verify & Unlock") 
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))
                TextButton(onClick = { 
                    onSignOut()
                    isRestoringSession = false
                    email = ""
                    password = ""
                    isHardLocked = false
                }) {
                    Text("Sign in with a different account", color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
        } else {
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

                            if (authAttemptManager.needsCaptcha() && !captchaVerified) {
                                showCaptchaChallenge = true
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
                                    captchaVerified = false
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
                                            captchaVerified = false
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
