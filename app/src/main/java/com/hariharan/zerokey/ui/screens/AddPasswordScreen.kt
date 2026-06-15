package com.hariharan.zerokey.ui.screens

import android.widget.Toast
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Refresh
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
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hariharan.zerokey.utils.PasswordStrength
import com.hariharan.zerokey.utils.PasswordUtils
import com.hariharan.zerokey.viewmodel.PasswordViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddPasswordScreen(
    viewModel: PasswordViewModel,
    initialPassword: String = "",
    onBack: () -> Unit,
    onGenerateClick: () -> Unit
) {
    val context = LocalContext.current
    var serviceName by remember { mutableStateOf("") }
    var username by remember { mutableStateOf("") }
    var password by remember { mutableStateOf(initialPassword) }
    var notes by remember { mutableStateOf("") }
    var isSaving by remember { mutableStateOf(false) }

    // Sync state if initialPassword changes (e.g. returning from generator)
    LaunchedEffect(initialPassword) {
        if (initialPassword.isNotEmpty()) {
            password = initialPassword
        }
    }

    val strength = remember(password) { PasswordUtils.calculateStrength(password) }
    val isDuplicate = remember(password) { viewModel.isDuplicatePassword(password) }

    val surfaceColor = MaterialTheme.colorScheme.surface

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                brush = Brush.verticalGradient(
                    colors = listOf(
                        surfaceColor,
                        MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.05f)
                    )
                )
            )
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .statusBarsPadding()
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 16.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = onBack) {
                    Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                }
                Text(
                    text = "New Credential",
                    style = MaterialTheme.typography.headlineSmall.copy(
                        fontWeight = FontWeight.Black,
                        letterSpacing = (-1).sp
                    ),
                    modifier = Modifier.padding(start = 8.dp)
                )
            }

            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 24.dp)
                    .verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                AddTransparentTextField(
                    value = serviceName,
                    onValueChange = { serviceName = it },
                    label = "Service Name",
                    placeholder = "e.g. Google, Github",
                    capitalization = KeyboardCapitalization.Words
                )

                AddTransparentTextField(
                    value = username,
                    onValueChange = { username = it },
                    label = "Username / Email",
                    placeholder = "yourname@example.com"
                )

                // Secure Password Field with Generator Link
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    AddTransparentTextField(
                        value = password,
                        onValueChange = { password = it },
                        label = "Password",
                        placeholder = "••••••••",
                        keyboardType = KeyboardType.Password,
                        isPassword = true,
                        trailingIcon = {
                            IconButton(onClick = onGenerateClick) {
                                Icon(
                                    Icons.Default.Refresh, 
                                    contentDescription = "Generate",
                                    tint = MaterialTheme.colorScheme.primary
                                )
                            }
                        }
                    )

                    if (password.isNotEmpty()) {
                        StrengthMeter(strength)
                        if (isDuplicate) {
                            Text(
                                text = "Warning: This password is used in another account!",
                                color = MaterialTheme.colorScheme.error,
                                style = MaterialTheme.typography.labelSmall,
                                fontWeight = FontWeight.Bold
                            )
                        }
                    }
                }

                AddTransparentTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = "Notes",
                    placeholder = "Optional account details",
                    singleLine = false
                )

                Spacer(modifier = Modifier.height(32.dp))

                Button(
                    onClick = {
                        if (serviceName.isNotBlank() && password.isNotBlank()) {
                            isSaving = true
                            viewModel.addPassword(
                                service = serviceName,
                                username = username, 
                                password = password, 
                                notes = notes,
                                onComplete = { 
                                    isSaving = false
                                    onBack() 
                                },
                                onError = { error ->
                                    isSaving = false
                                    Toast.makeText(context, error, Toast.LENGTH_LONG).show()
                                }
                            )
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
                    enabled = serviceName.isNotBlank() && password.isNotBlank() && !isSaving
                ) {
                    if (isSaving) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            color = MaterialTheme.colorScheme.surface,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text("Securely Save", fontWeight = FontWeight.Bold)
                    }
                }
                
                Spacer(modifier = Modifier.height(32.dp))
            }
        }
    }
}

@Composable
fun AddTransparentTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    placeholder: String = "",
    keyboardType: KeyboardType = KeyboardType.Text,
    capitalization: KeyboardCapitalization = KeyboardCapitalization.None,
    singleLine: Boolean = true,
    isPassword: Boolean = false,
    trailingIcon: @Composable (() -> Unit)? = null
) {
    var passwordVisible by remember { mutableStateOf(false) }
    
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            fontWeight = FontWeight.Medium
        )
        TextField(
            value = value,
            onValueChange = onValueChange,
            placeholder = { Text(placeholder, color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)) },
            modifier = Modifier.fillMaxWidth(),
            trailingIcon = if (isPassword) {
                {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        IconButton(onClick = { passwordVisible = !passwordVisible }) {
                            Icon(
                                imageVector = if (passwordVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                contentDescription = null
                            )
                        }
                        trailingIcon?.invoke()
                    }
                }
            } else trailingIcon,
            singleLine = singleLine,
            visualTransformation = if (isPassword && !passwordVisible) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = KeyboardOptions(
                keyboardType = keyboardType,
                capitalization = capitalization
            ),
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
}

@Composable
fun StrengthMeter(strength: PasswordStrength) {
    val color by animateColorAsState(
        targetValue = when (strength) {
            PasswordStrength.EMPTY -> Color.Transparent
            PasswordStrength.WEAK -> Color(0xFFF44336)
            PasswordStrength.MEDIUM -> Color(0xFFFFC107)
            PasswordStrength.STRONG -> Color(0xFF4CAF50)
            PasswordStrength.VERY_STRONG -> Color(0xFF00C853)
        }
    )

    val label = when (strength) {
        PasswordStrength.EMPTY -> ""
        PasswordStrength.WEAK -> "Weak"
        PasswordStrength.MEDIUM -> "Medium"
        PasswordStrength.STRONG -> "Strong"
        PasswordStrength.VERY_STRONG -> "Very Strong"
    }

    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        LinearProgressIndicator(
            progress = {
                when (strength) {
                    PasswordStrength.EMPTY -> 0f
                    PasswordStrength.WEAK -> 0.25f
                    PasswordStrength.MEDIUM -> 0.5f
                    PasswordStrength.STRONG -> 0.75f
                    PasswordStrength.VERY_STRONG -> 1f
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(6.dp)
                .background(Color.Transparent, RoundedCornerShape(4.dp)),
            color = color,
            trackColor = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.3f),
            strokeCap = androidx.compose.ui.graphics.StrokeCap.Round
        )
        Text(
            text = "Password Strength: $label",
            style = MaterialTheme.typography.labelSmall,
            color = color,
            fontWeight = FontWeight.Bold
        )
    }
}
