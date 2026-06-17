package com.hariharan.zerokey.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricPrompt
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.security.SecurityEventManager
import com.hariharan.zerokey.utils.SecureClipboard
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun VaultScreen(
    viewModel: PasswordViewModel,
    onAddClick: () -> Unit,
    onSecurityActivityClick: () -> Unit = {},
    onPasswordHealthClick: () -> Unit = {},
    onSecurityDashboardClick: () -> Unit = {},
    onSharingClick: () -> Unit = {},
    onSyncClick: () -> Unit = {},
    onSettingsClick: () -> Unit = {}
) {
    val passwords = viewModel.passwords
    val searchQuery = viewModel.searchQuery
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    var showMenu by remember { mutableStateOf(false) }
    var showOfflineModeDialog by remember { mutableStateOf(false) }

    // Export File Launcher
    val exportLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/json")
    ) { uri ->
        uri?.let {
            scope.launch {
                val tempFile = File(context.cacheDir, "vault_export.json")
                viewModel.exportVault(context, tempFile) { success ->
                    if (success) {
                        try {
                            context.contentResolver.openOutputStream(it)?.use { output ->
                                tempFile.inputStream().copyTo(output)
                            }
                            Toast.makeText(context, "Vault exported successfully", Toast.LENGTH_SHORT).show()
                        } catch (e: Exception) {
                            Toast.makeText(context, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
                        }
                    } else {
                        Toast.makeText(context, "Export failed", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }
    }

    // Import File Launcher
    val importLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.GetContent()
    ) { uri ->
        uri?.let {
            scope.launch {
                val tempFile = File(context.cacheDir, "vault_import.json")
                try {
                    context.contentResolver.openInputStream(it)?.use { input ->
                        tempFile.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                    viewModel.importVault(tempFile) { success ->
                        if (success) {
                            Toast.makeText(context, "Vault imported and merged", Toast.LENGTH_SHORT).show()
                        } else {
                            Toast.makeText(context, "Import failed: Invalid file or key", Toast.LENGTH_SHORT).show()
                        }
                    }
                } catch (e: Exception) {
                    Toast.makeText(context, "Import failed: ${e.message}", Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    val surfaceColor = MaterialTheme.colorScheme.surface

    if (showOfflineModeDialog) {
        AlertDialog(
            onDismissRequest = { showOfflineModeDialog = false },
            title = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.error
                    )
                    Spacer(Modifier.width(8.dp))
                    Text("Activate Stealth Protocol?")
                }
            },
            text = {
                Text(
                    "This will disable all cloud synchronization. Your data will stay local-only.\n\n" +
                            "WARNING: If you lose this device or uninstall the app, your passwords CANNOT be recovered without a manual backup."
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        viewModel.toggleOfflineMode(context, true)
                        showOfflineModeDialog = false
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Activate")
                }
            },
            dismissButton = {
                TextButton(onClick = { showOfflineModeDialog = false }) {
                    Text("Cancel")
                }
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
            // Premium Header with Options Menu
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "ZeroKey",
                    style = MaterialTheme.typography.headlineMedium.copy(
                        fontWeight = FontWeight.Black,
                        letterSpacing = (-1.5).sp
                    )
                )
                
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Surface(
                        onClick = onAddClick,
                        shape = CircleShape,
                        color = MaterialTheme.colorScheme.onSurface,
                        contentColor = MaterialTheme.colorScheme.surface
                    ) {
                        Icon(
                            Icons.Default.Add,
                            contentDescription = "Add",
                            modifier = Modifier.padding(8.dp).size(24.dp)
                        )
                    }
                    
                    Spacer(modifier = Modifier.width(8.dp))
                    
                    Box {
                        IconButton(onClick = { showMenu = true }) {
                            Icon(Icons.Default.MoreVert, contentDescription = "Menu")
                        }
                        
                        DropdownMenu(
                            expanded = showMenu,
                            onDismissRequest = { showMenu = false },
                            modifier = Modifier.background(MaterialTheme.colorScheme.surface)
                        ) {
                            DropdownMenuItem(
                                text = { Text("Cloud Sync") },
                                leadingIcon = { Icon(Icons.Default.CloudSync, null) },
                                onClick = {
                                    showMenu = false
                                    onSyncClick()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Security Dashboard") },
                                leadingIcon = { Icon(Icons.Default.Shield, null) },
                                onClick = {
                                    showMenu = false
                                    onSecurityDashboardClick()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Secure Sharing") },
                                leadingIcon = { Icon(Icons.Default.Share, null) },
                                onClick = {
                                    showMenu = false
                                    onSharingClick()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Security Activity") },
                                leadingIcon = { Icon(Icons.Default.History, null) },
                                onClick = {
                                    showMenu = false
                                    onSecurityActivityClick()
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Settings") },
                                leadingIcon = { Icon(Icons.Default.Settings, null) },
                                onClick = {
                                    showMenu = false
                                    onSettingsClick()
                                }
                            )
                            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                            DropdownMenuItem(
                                text = {
                                    Row(verticalAlignment = Alignment.CenterVertically) {
                                        Text("Offline Mode")
                                        Spacer(Modifier.width(8.dp))
                                        Switch(
                                            checked = viewModel.isOfflineMode,
                                            onCheckedChange = { enabled ->
                                                if (enabled) {
                                                    showOfflineModeDialog = true
                                                } else {
                                                    viewModel.toggleOfflineMode(context, false)
                                                }
                                            },
                                            modifier = Modifier.scale(0.7f)
                                        )
                                    }
                                },
                                onClick = { }
                            )
                            HorizontalDivider(modifier = Modifier.padding(vertical = 4.dp))
                            DropdownMenuItem(
                                text = { Text("Export Vault") },
                                leadingIcon = { Icon(Icons.Default.FileUpload, null) },
                                onClick = {
                                    showMenu = false
                                    val activity = context as? FragmentActivity
                                    if (activity != null) {
                                        triggerExportAuth(activity) {
                                            exportLauncher.launch("ZeroKey_Backup.json")
                                        }
                                    } else {
                                        // Fallback for non-activity context if any
                                        exportLauncher.launch("ZeroKey_Backup.json")
                                    }
                                }
                            )
                            DropdownMenuItem(
                                text = { Text("Import Vault") },
                                leadingIcon = { Icon(Icons.Default.FileDownload, null) },
                                onClick = {
                                    showMenu = false
                                    importLauncher.launch("application/json")
                                }
                            )
                        }
                    }
                }
            }

            // Minimalist Search
            VaultTransparentTextField(
                value = searchQuery,
                onValueChange = { viewModel.onSearchQueryChange(it) },
                label = "Search vault",
                leadingIcon = Icons.Default.Search,
                modifier = Modifier.padding(horizontal = 24.dp, vertical = 8.dp)
            )

            // Quick Stats Row (Premium Minimalist)
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 24.dp, vertical = 16.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatCard(
                    label = "Score",
                    value = "${viewModel.healthReport.score}",
                    modifier = Modifier.weight(1f),
                    color = when {
                        viewModel.healthReport.score > 80 -> Color(0xFF4CAF50)
                        viewModel.healthReport.score > 50 -> Color(0xFFFFC107)
                        else -> Color(0xFFF44336)
                    }
                )
                StatCard(
                    label = "Items",
                    value = "${passwords.size}",
                    modifier = Modifier.weight(1f)
                )
            }

            // Security Alerts Section
            AnimatedVisibility(
                visible = viewModel.securityAlerts.isNotEmpty(),
                enter = expandVertically() + fadeIn(),
                exit = shrinkVertically() + fadeOut()
            ) {
                SecurityAlertsCard(
                    alerts = viewModel.securityAlerts,
                    onDismiss = { /* In a real app, mark alerts as read/dismissed */ }
                )
            }

            if (passwords.isEmpty()) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = if (searchQuery.isEmpty()) "Your vault is empty." else "No matches found.",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(top = 8.dp, bottom = 100.dp)
                ) {
                    items(passwords, key = { it.id }) { item ->
                        PasswordItemCard(item, viewModel)
                    }
                }
            }
        }
    }
}

@Composable
fun SecurityAlertsCard(
    alerts: List<SecurityEventManager.SecurityAlert>,
    onDismiss: () -> Unit
) {
    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 8.dp),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.1f),
        border = androidx.compose.foundation.BorderStroke(1.dp, MaterialTheme.colorScheme.error.copy(alpha = 0.2f))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    Icons.Default.Security,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(20.dp)
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text(
                    text = "Security Alerts",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.error
                )
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            
            alerts.forEach { alert ->
                Column(modifier = Modifier.padding(bottom = 8.dp)) {
                    Text(
                        text = alert.title,
                        style = MaterialTheme.typography.bodyMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = alert.message,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        }
    }
}

@Composable
fun VaultTransparentTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    leadingIcon: androidx.compose.ui.graphics.vector.ImageVector,
    modifier: Modifier = Modifier
) {
    TextField(
        value = value,
        onValueChange = onValueChange,
        label = { Text(label) },
        modifier = modifier.fillMaxWidth(),
        leadingIcon = { Icon(leadingIcon, contentDescription = null, modifier = Modifier.size(20.dp)) },
        singleLine = true,
        colors = TextFieldDefaults.colors(
            focusedContainerColor = Color.Transparent,
            unfocusedContainerColor = Color.Transparent,
            disabledContainerColor = Color.Transparent,
            focusedIndicatorColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.1f),
            unfocusedIndicatorColor = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f),
            focusedLabelColor = MaterialTheme.colorScheme.onSurface,
            unfocusedLabelColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.4f)
        )
    )
}

@Composable
fun StatCard(label: String, value: String, modifier: Modifier = Modifier, color: Color = MaterialTheme.colorScheme.onSurface) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Text(label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text(value, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = color)
        }
    }
}

@Composable
fun PasswordItemCard(item: PasswordItem, viewModel: PasswordViewModel) {
    var visible by remember { mutableStateOf(false) }
    var showDeleteDialog by remember { mutableStateOf(false) }
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()

    LaunchedEffect(visible) {
        if (visible) {
            viewModel.logPasswordViewed(item.serviceName)
            delay(10000)
            visible = false
        }
    }

    if (showDeleteDialog) {
        AlertDialog(
            onDismissRequest = { showDeleteDialog = false },
            title = { Text("Delete Credential") },
            text = { Text("Are you sure you want to delete the password for ${item.serviceName}? This cannot be undone.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        viewModel.deletePassword(item)
                        showDeleteDialog = false
                    },
                    colors = ButtonDefaults.textButtonColors(contentColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Delete")
                }
            },
            dismissButton = {
                TextButton(onClick = { showDeleteDialog = false }) {
                    Text("Cancel")
                }
            }
        )
    }

    Surface(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 24.dp, vertical = 8.dp),
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        onClick = { visible = !visible }
    ) {
        Row(
            modifier = Modifier
                .padding(20.dp)
                .fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = item.serviceName,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = item.username,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f)
                )
                
                Spacer(modifier = Modifier.height(12.dp))
                
                Text(
                    text = if (visible) item.password else "••••••••",
                    style = MaterialTheme.typography.bodyLarge,
                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                    letterSpacing = if (visible) 0.sp else 4.sp,
                    color = if (visible) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }

            Row {
                IconButton(
                    onClick = {
                        SecureClipboard.copy(context, "ZeroKey", item.password)
                        viewModel.logPasswordCopied(item.serviceName)
                    },
                    colors = IconButtonDefaults.iconButtonColors(
                        contentColor = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f)
                    )
                ) {
                    Icon(Icons.Default.ContentCopy, contentDescription = "Copy", modifier = Modifier.size(20.dp))
                }

                IconButton(
                    onClick = { showDeleteDialog = true },
                    colors = IconButtonDefaults.iconButtonColors(
                        contentColor = MaterialTheme.colorScheme.error.copy(alpha = 0.7f)
                    )
                ) {
                    Icon(Icons.Default.Delete, contentDescription = "Delete", modifier = Modifier.size(20.dp))
                }
            }
        }
    }
}

private fun triggerExportAuth(activity: FragmentActivity, onSuccess: () -> Unit) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onSuccess()
            }
        })

    val builder = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Export Authorization")
        .setSubtitle("Confirm your identity to export the vault")
    if (android.os.Build.VERSION.SDK_INT >= 30) {
        builder.setAllowedAuthenticators(
            androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or
            androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
    } else {
        builder.setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG)
        builder.setNegativeButtonText("Cancel")
    }
    val promptInfo = builder.build()

    biometricPrompt.authenticate(promptInfo)
}


