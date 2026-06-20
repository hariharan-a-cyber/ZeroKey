package com.hariharan.zerokey.ui.screens

import android.os.Build
import android.provider.MediaStore
import android.content.ContentValues
import android.os.Environment
import android.widget.Toast
import androidx.fragment.app.FragmentActivity
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.automirrored.filled.ExitToApp
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Key
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material.icons.filled.Visibility
import androidx.compose.material.icons.filled.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.DialogProperties
import java.io.File
import java.io.FileOutputStream
import kotlinx.coroutines.launch
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import com.google.firebase.firestore.SetOptions
import com.hariharan.zerokey.core.security.MasterPasswordManager
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import com.hariharan.zerokey.utils.SecureClipboard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    viewModel: PasswordViewModel,
    masterPasswordManager: MasterPasswordManager,
    biometricUnlockManager: com.hariharan.zerokey.security.BiometricVaultUnlockManager,
    onBack: () -> Unit,
    onManageDevices: () -> Unit,
    onSignOut: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val surfaceColor = MaterialTheme.colorScheme.surface
    
    var currentTimeout by remember { mutableStateOf(masterPasswordManager.getAuthTimeout(context)) }
    var lockOnExit by remember { mutableStateOf(masterPasswordManager.shouldLockOnExit(context)) }
    var bioEnabled by remember { mutableStateOf(biometricUnlockManager.isEnrolled()) }
    var recoveryCodeShown by remember { mutableStateOf<String?>(null) }
    var showTimeoutDialog by remember { mutableStateOf(false) }
    var showRotationConfirm by remember { mutableStateOf(false) }
    var showPasswordChange by remember { mutableStateOf(false) }
    var isRotating by remember { mutableStateOf(false) }
    var isChangingPassword by remember { mutableStateOf(false) }
    var showRecoveryWarnDialog by remember { mutableStateOf(false) }
    var showLockWarnDialog by remember { mutableStateOf(false) }

    val timeoutOptions = listOf(
        TimeoutOption("Always Require", 0L),
        TimeoutOption("15 Seconds", 15_000L),
        TimeoutOption("30 Seconds", 30_000L),
        TimeoutOption("60 Seconds", 60_000L)
    )

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Settings", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(containerColor = Color.Transparent)
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
        val scrollState = rememberScrollState()
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
                .padding(padding)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(scrollState)
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                AutofillSetupCard()
                Text(
                    "Security Policy",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold
                )

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    onClick = { showTimeoutDialog = true }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Security, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Autofill Auth Timeout", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text(
                                text = timeoutOptions.find { it.value == currentTimeout }?.label ?: "60 Seconds",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Text(
                    "This setting controls how often ZeroKey requires a biometric check before autofilling your credentials into other apps.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    modifier = Modifier.padding(horizontal = 8.dp)
                )

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Refresh, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Lock on App Exit", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text(
                                text = "Wipe keys from memory when backgrounded.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = lockOnExit,
                            onCheckedChange = {
                                if (!it) {
                                    showLockWarnDialog = true
                                } else {
                                    lockOnExit = true
                                    masterPasswordManager.setLockOnExit(context, true)
                                    Toast.makeText(context, "Auto-lock enabled", Toast.LENGTH_SHORT).show()
                                }
                            }
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Key, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Biometric Unlock", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text(
                                text = "Open your vault with fingerprint/face on this device. Your master password still controls and recovers the vault.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Switch(
                            checked = bioEnabled,
                            onCheckedChange = { wantOn ->
                                val activity = context as? FragmentActivity
                                if (wantOn) {
                                    val raw = masterPasswordManager.getVaultKey()?.encoded
                                    if (activity == null || raw == null) {
                                        Toast.makeText(context, "Unlock the vault first.", Toast.LENGTH_SHORT).show()
                                    } else if (!biometricUnlockManager.isSupported()) {
                                        Toast.makeText(context, "Biometric unlock needs Android 11+ with biometrics enrolled.", Toast.LENGTH_SHORT).show()
                                    } else {
                                        biometricUnlockManager.enroll(activity, raw) { ok ->
                                            java.util.Arrays.fill(raw, 0)
                                            bioEnabled = ok
                                            Toast.makeText(context, if (ok) "Biometric unlock enabled." else "Could not enable biometric unlock.", Toast.LENGTH_SHORT).show()
                                        }
                                    }
                                } else {
                                    biometricUnlockManager.clear()
                                    bioEnabled = false
                                    Toast.makeText(context, "Biometric unlock disabled.", Toast.LENGTH_SHORT).show()
                                }
                            }
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    onClick = { showPasswordChange = true }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Key, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Change Master Password", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text(
                                text = "Update your vault's main protection key.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    onClick = { onManageDevices() }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Devices, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Manage Trusted Devices", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text(
                                text = "Audit or revoke vault access.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    onClick = {
                        if (masterPasswordManager.getVaultKey() == null) {
                            Toast.makeText(context, "Unlock the vault first.", Toast.LENGTH_SHORT).show()
                        } else {
                            showRecoveryWarnDialog = true
                        }
                    }
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Security, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Recovery Key", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text(
                                text = "Generate a one-time code to reset a forgotten master password without losing data. Save it somewhere safe.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }

                Spacer(Modifier.height(16.dp))

                Text(
                    "Advanced Cryptography",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold
                )

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.1f),
                    onClick = { showRotationConfirm = true },
                    enabled = !isRotating
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.Refresh, null, tint = MaterialTheme.colorScheme.error)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Rotate Vault Key", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.error)
                            Text(
                                text = "Emergency: Re-encrypt entire vault with a brand new master key.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error.copy(alpha = 0.8f)
                            )
                        }
                        if (isRotating) {
                            CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp)
                        }
                    }
                }

                Text(
                    "Use this if you suspect your device was compromised. It will invalidate all previous backups and sync snapshots.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                    modifier = Modifier.padding(horizontal = 8.dp)
                )

                Spacer(Modifier.height(16.dp))

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.1f),
                    onClick = {
                        scope.launch {
                            viewModel.lockVault()
                            masterPasswordManager.lockVault()
                            biometricUnlockManager.clear()
                            onSignOut()
                        }
                    }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.AutoMirrored.Filled.ExitToApp, null, tint = MaterialTheme.colorScheme.error)
                        Spacer(Modifier.width(16.dp))
                        Column {
                            Text("Sign Out", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold, color = MaterialTheme.colorScheme.error)
                            Text(
                                text = "Lock your vault and return to login.",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.error.copy(alpha = 0.7f)
                            )
                        }
                    }
                }
            }
        }
    }

    if (showLockWarnDialog) {
        AlertDialog(
            onDismissRequest = { showLockWarnDialog = false },
            icon = { Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Disable Auto-Lock?") },
            text = {
                Text("Your vault key will stay in memory even when the app is backgrounded. This is convenient but allows anyone with access to your unlocked phone to see your passwords.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        lockOnExit = false
                        masterPasswordManager.setLockOnExit(context, false)
                        showLockWarnDialog = false
                        Toast.makeText(context, "Security reduced: Auto-lock disabled", Toast.LENGTH_SHORT).show()
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) { Text("Disable Security") }
            },
            dismissButton = {
                TextButton(onClick = { showLockWarnDialog = false }) { Text("Keep Protected") }
            }
        )
    }

    if (showRecoveryWarnDialog) {
        AlertDialog(
            onDismissRequest = { showRecoveryWarnDialog = false },
            icon = { Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Generate New Recovery Keys?") },
            text = {
                Text("This will create 5 new recovery keys. Each code is 32 characters long and can be used once to reset your password. Your previous recovery keys will stop working immediately.")
            },
            confirmButton = {
                Button(
                    onClick = {
                        showRecoveryWarnDialog = false
                        val material = masterPasswordManager.createRecoveryMaterial()
                        masterPasswordManager.saveRecoveryBlobLocal(context, material.blobs)
                        FirebaseAuth.getInstance().currentUser?.uid?.let { uid ->
                            FirebaseFirestore.getInstance().collection("users").document(uid).set(
                                mapOf(
                                    "recoveryBlobs" to material.blobs.map { mapOf("blob" to it.blobB64, "iv" to it.ivB64) }
                                ),
                                SetOptions.merge()
                            )
                        }
                        recoveryCodeShown = material.recoveryCode
                    }
                ) {
                    Text("Generate New Keys")
                }
            },
            dismissButton = {
                TextButton(onClick = { showRecoveryWarnDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    if (recoveryCodeShown != null) {
        AlertDialog(
            onDismissRequest = { recoveryCodeShown = null },
            properties = DialogProperties(usePlatformDefaultWidth = false),
            modifier = Modifier.fillMaxWidth(0.95f),
            icon = { Icon(Icons.Default.Security, null, tint = MaterialTheme.colorScheme.primary) },
            title = { Text("Your Recovery Keys") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text(
                        "Save these codes safely to reset your master password.",
                        style = MaterialTheme.typography.bodySmall,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Text(
                        "Note: Each line is a SEPARATE 32-character key. Enter ONE code fully to recover.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.primary,
                        fontWeight = FontWeight.Bold
                    )
                    
                    Text(
                        "If BOTH password and ALL recovery codes are lost, there is NO way to recover your vault.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Bold,
                        textAlign = TextAlign.Center
                    )

                    Surface(
                        color = MaterialTheme.colorScheme.surfaceVariant,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Column(
                            modifier = Modifier.padding(12.dp),
                            verticalArrangement = Arrangement.spacedBy(4.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            recoveryCodeShown?.split("-")?.forEach { segment ->
                                Text(
                                    segment,
                                    style = MaterialTheme.typography.bodySmall.copy(
                                        fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                        fontWeight = FontWeight.Bold,
                                        letterSpacing = 0.5.sp
                                    ),
                                    maxLines = 1
                                )
                            }
                        }
                    }
                }
            },
            confirmButton = {
                    Button(
                        onClick = {
                            SecureClipboard.copy(context, recoveryCodeShown ?: "")
                            Toast.makeText(context, "Copied. Store it safely.", Toast.LENGTH_SHORT).show()
                            recoveryCodeShown = null
                        }
                    ) { Text("Copy & Close", style = MaterialTheme.typography.labelMedium) }
            }
        )
    }

    if (showRotationConfirm) {
        AlertDialog(
            onDismissRequest = { showRotationConfirm = false },
            icon = { Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Confirm Vault Rotation?") },
            text = { Text("This will re-encrypt every single item in your database with a new random key. This is a heavy operation and cannot be undone.") },
            confirmButton = {
                Button(
                    onClick = {
                        showRotationConfirm = false
                        val activity = context as? androidx.fragment.app.FragmentActivity
                        val runRotation = {
                            isRotating = true
                            viewModel.rotateVaultKey(context) { success ->
                                isRotating = false
                                if (success) {
                                    // Rotation changed the vault key: old recovery + biometric copies are stale.
                                    masterPasswordManager.clearRecoveryBlobLocal(context)
                                    biometricUnlockManager.clear()
                                    FirebaseAuth.getInstance().currentUser?.uid?.let { uid ->
                                        FirebaseFirestore.getInstance().collection("users").document(uid).update(
                                            "recoveryBlobs", com.google.firebase.firestore.FieldValue.delete(),
                                            "recoveryWrappedVaultKey", com.google.firebase.firestore.FieldValue.delete(),
                                            "recoveryIv", com.google.firebase.firestore.FieldValue.delete()
                                        )
                                    }
                                    Toast.makeText(context, "Vault Key Rotated. Re-create your recovery key.", Toast.LENGTH_LONG).show()
                                } else {
                                    Toast.makeText(context, "Rotation Failed", Toast.LENGTH_LONG).show()
                                }
                            }
                        }

                        if (biometricUnlockManager.isSupported() && activity != null) {
                            biometricUnlockManager.unlock(activity) { rawKey ->
                                if (rawKey != null) {
                                    java.util.Arrays.fill(rawKey, 0)
                                    runRotation()
                                } else {
                                    Toast.makeText(context, "Authentication required", Toast.LENGTH_SHORT).show()
                                }
                            }
                        } else {
                            runRotation()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    if (isRotating) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp, color = Color.White)
                    } else {
                        Text("Rotate Now")
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { showRotationConfirm = false }) { Text("Cancel") }
            }
        )
    }

    if (showPasswordChange) {
        var currentPass by remember { mutableStateOf("") }
        var currentPassVisible by remember { mutableStateOf(false) }
        var newPass by remember { mutableStateOf("") }
        var confirmPass by remember { mutableStateOf("") }
        var newPassVisible by remember { mutableStateOf(false) }
        var confirmPassVisible by remember { mutableStateOf(false) }
        var error by remember { mutableStateOf<String?>(null) }

        AlertDialog(
            onDismissRequest = { showPasswordChange = false },
            title = { Text("Change Master Password") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("This will re-wrap your vault with a new key and upgrade security parameters.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = currentPass,
                        onValueChange = { currentPass = it },
                        label = { Text("Current Master Password") },
                        visualTransformation = if (currentPassVisible) androidx.compose.ui.text.input.VisualTransformation.None else androidx.compose.ui.text.input.PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { currentPassVisible = !currentPassVisible }) {
                                Icon(
                                    imageVector = if (currentPassVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = null
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = newPass,
                        onValueChange = { newPass = it },
                        label = { Text("New Master Password") },
                        visualTransformation = if (newPassVisible) androidx.compose.ui.text.input.VisualTransformation.None else androidx.compose.ui.text.input.PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { newPassVisible = !newPassVisible }) {
                                Icon(
                                    imageVector = if (newPassVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = null
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                    OutlinedTextField(
                        value = confirmPass,
                        onValueChange = { confirmPass = it },
                        label = { Text("Confirm New Password") },
                        visualTransformation = if (confirmPassVisible) androidx.compose.ui.text.input.VisualTransformation.None else androidx.compose.ui.text.input.PasswordVisualTransformation(),
                        trailingIcon = {
                            IconButton(onClick = { confirmPassVisible = !confirmPassVisible }) {
                                Icon(
                                    imageVector = if (confirmPassVisible) Icons.Default.VisibilityOff else Icons.Default.Visibility,
                                    contentDescription = null
                                )
                            }
                        },
                        modifier = Modifier.fillMaxWidth()
                    )
                    if (error != null) {
                        Text(error!!, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (currentPass.isEmpty()) {
                            error = "Enter your current password"
                        } else if (newPass.length < 6) {
                            error = "Password must be at least 6 characters"
                        } else if (newPass != confirmPass) {
                            error = "Passwords do not match"
                        } else {
                            // Verify current password first.
                            try {
                                masterPasswordManager.unlockVault(context, currentPass.toCharArray())
                            } catch (e: Exception) {
                                error = "Current password is incorrect"
                                isChangingPassword = false
                                return@Button
                            }
                            isChangingPassword = true
                            viewModel.changeMasterPassword(context, newPass) { result ->
                                isChangingPassword = false
                                when (result) {
                                    is com.hariharan.zerokey.security.AuthResult.Success -> {
                                        // Old recovery + biometric copies wrapped the OLD vault key; invalidate them.
                                        masterPasswordManager.clearRecoveryBlobLocal(context)
                                        biometricUnlockManager.clear()
                                        bioEnabled = false
                                        FirebaseAuth.getInstance().currentUser?.uid?.let { uid ->
                                            FirebaseFirestore.getInstance().collection("users").document(uid).update(
                                                "recoveryBlobs", com.google.firebase.firestore.FieldValue.delete()
                                            )
                                        }
                                        showPasswordChange = false
                                        Toast.makeText(context, "Master Password Updated. Re-create your recovery key.", Toast.LENGTH_LONG).show()
                                    }
                                    is com.hariharan.zerokey.security.AuthResult.Error -> {
                                        error = result.message
                                    }
                                }
                            }
                        }
                    },
                    enabled = !isChangingPassword
                ) {
                    if (isChangingPassword) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp), strokeWidth = 2.dp, color = Color.White)
                    } else {
                        Text("Update Password")
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { showPasswordChange = false }) { Text("Cancel") }
            }
        )
    }

    if (showTimeoutDialog) {
        AlertDialog(
            onDismissRequest = { showTimeoutDialog = false },
            title = { Text("Select Timeout") },
            text = {
                Column(Modifier.selectableGroup()) {
                    timeoutOptions.forEach { option ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .height(56.dp)
                                .selectable(
                                    selected = (option.value == currentTimeout),
                                    onClick = {
                                        currentTimeout = option.value
                                        masterPasswordManager.setAuthTimeout(context, option.value)
                                        showTimeoutDialog = false
                                    },
                                    role = Role.RadioButton
                                )
                                .padding(horizontal = 16.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = (option.value == currentTimeout),
                                onClick = null
                            )
                            Text(
                                text = option.label,
                                style = MaterialTheme.typography.bodyLarge,
                                modifier = Modifier.padding(start = 16.dp)
                            )
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showTimeoutDialog = false }) {
                    Text("Close")
                }
            }
        )
    }
}

data class TimeoutOption(val label: String, val value: Long)
