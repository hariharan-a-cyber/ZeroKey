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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hariharan.zerokey.security.FirebaseAuthenticator
import com.hariharan.zerokey.security.MasterPasswordManager
import kotlinx.coroutines.launch

@Composable
fun AuthScreen(
    authenticator: FirebaseAuthenticator,
    onAuthSuccess: () -> Unit
) {
    var isLogin by remember { mutableStateOf(true) }
    var email by remember { mutableStateOf("") }
    var password by remember { mutableStateOf("") }
    var passwordVisible by remember { mutableStateOf(false) }
    var isLoading by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    
    val scope = rememberCoroutineScope()
    val context = LocalContext.current

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
                text = "The invisible vault for your digital life.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                modifier = Modifier.padding(top = 8.dp, bottom = 48.dp),
                textAlign = TextAlign.Center
            )

            // Minimalist Form
            TransparentTextField(
                value = email,
                onValueChange = { email = it },
                label = "Email",
                leadingIcon = Icons.Default.Email,
                keyboardType = KeyboardType.Email
            )

            Spacer(modifier = Modifier.height(20.dp))

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
                        val user = if (isLogin) {
                            authenticator.signIn(email, password)
                        } else {
                            authenticator.signUp(email, password)
                        }
                        
                        if (user != null) {
                            try {
                                // Initialize the Vault session with the Master Password
                                if (!MasterPasswordManager.isSetup(context)) {
                                    MasterPasswordManager.setupVault(context, password.toCharArray())
                                } else {
                                    MasterPasswordManager.unlockVault(context, password.toCharArray())
                                }
                                onAuthSuccess()
                            } catch (e: Exception) {
                                errorMessage = "Vault unlock failed: ${e.message}"
                            }
                        } else {
                            errorMessage = if (isLogin) "Invalid credentials" else "Signup failed"
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
                enabled = !isLoading && email.isNotEmpty() && password.length >= 6
            ) {
                if (isLoading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        strokeWidth = 2.dp,
                        color = MaterialTheme.colorScheme.surface
                    )
                } else {
                    Text(
                        text = if (isLogin) "Sign In" else "Create Account",
                        fontWeight = FontWeight.Bold,
                        letterSpacing = 0.5.sp
                    )
                }
            }

            Spacer(modifier = Modifier.height(16.dp))

            // Elegant Google Integration
            OutlinedButton(
                onClick = {
                    scope.launch {
                        isLoading = true
                        errorMessage = null
                        val user = authenticator.signInWithGoogle(context, "1034703214734-dc9qa6ohcb2l2lvl11ict77q4k39q728.apps.googleusercontent.com")
                        if (user != null) {
                            onAuthSuccess()
                        } else {
                            errorMessage = "Google Sign-In failed"
                        }
                        isLoading = false
                    }
                },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(60.dp),
                shape = RoundedCornerShape(20.dp),
                border = BorderStroke(width = 1.dp, color = MaterialTheme.colorScheme.outline.copy(alpha = 0.3f))
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        "Continue with Google",
                        color = MaterialTheme.colorScheme.onSurface,
                        fontWeight = FontWeight.Medium
                    )
                }
            }

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
