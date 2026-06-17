package com.hariharan.zerokey.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DeleteForever
import androidx.compose.material.icons.filled.Devices
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import androidx.biometric.BiometricPrompt
import com.hariharan.zerokey.security.DeviceTrustManager
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceManagementScreen(
    viewModel: PasswordViewModel,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val devices = viewModel.trustedDevices
    val isLoading = viewModel.isLoadingDevices
    
    val currentDeviceId = remember { 
        android.provider.Settings.Secure.getString(context.contentResolver, android.provider.Settings.Secure.ANDROID_ID) 
    }
    
    LaunchedEffect(Unit) {
        viewModel.refreshDeviceList()
    }
    
    var deviceToRevoke by remember { mutableStateOf<DeviceTrustManager.DeviceInfo?>(null) }
    var showPostRevokeRecommendation by remember { mutableStateOf(false) }

    val surfaceColor = MaterialTheme.colorScheme.surface

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Trusted Devices", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { viewModel.refreshDeviceList() }, enabled = !isLoading) {
                        Icon(Icons.Default.Refresh, "Refresh")
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(containerColor = Color.Transparent)
            )
        },
        containerColor = Color.Transparent
    ) { padding ->
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
            if (isLoading && devices.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else if (devices.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(
                        "No trusted devices found.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            } else {
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp)
                ) {
                    item {
                        Text(
                            "Audit and revoke access for devices that have connected to your vault.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                            modifier = Modifier.padding(bottom = 8.dp)
                        )
                    }

                    items(devices) { device ->
                        DeviceItemCard(
                            device = device,
                            isCurrent = device.deviceId == currentDeviceId,
                            onRevoke = { deviceToRevoke = device }
                        )
                    }
                }
            }
        }
    }

    if (deviceToRevoke != null) {
        AlertDialog(
            onDismissRequest = { deviceToRevoke = null },
            icon = { Icon(Icons.Default.Warning, null, tint = MaterialTheme.colorScheme.error) },
            title = { Text("Revoke Device Access?") },
            text = { Text("Are you sure you want to revoke access for \"${deviceToRevoke?.deviceName}\"? This device will no longer be able to sync or access your cloud vault.") },
            confirmButton = {
                Button(
                    onClick = {
                        val id = deviceToRevoke?.deviceId ?: return@Button
                        val activity = context as? FragmentActivity
                        if (activity != null) {
                            triggerRevocationAuth(activity) {
                                viewModel.revokeDevice(id) { success ->
                                    if (success) {
                                        Toast.makeText(context, "Access Revoked", Toast.LENGTH_SHORT).show()
                                        showPostRevokeRecommendation = true
                                    } else {
                                        Toast.makeText(context, "Revocation Failed", Toast.LENGTH_SHORT).show()
                                    }
                                    deviceToRevoke = null
                                }
                            }
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                ) {
                    Text("Confirm Revoke")
                }
            },
            dismissButton = {
                TextButton(onClick = { deviceToRevoke = null }) { Text("Cancel") }
            }
        )
    }

    if (showPostRevokeRecommendation) {
        AlertDialog(
            onDismissRequest = { showPostRevokeRecommendation = false },
            icon = { Icon(Icons.Default.Security, null, tint = MaterialTheme.colorScheme.primary) },
            title = { Text("Security Recommendation") },
            text = { Text("Device access has been revoked. To ensure your data is completely protected from the lost device, we strongly recommend rotating your Vault Key now.") },
            confirmButton = {
                Button(onClick = {
                    showPostRevokeRecommendation = false
                    onBack() // Return to settings where rotation is available
                }) {
                    Text("Go to Security Maintenance")
                }
            },
            dismissButton = {
                TextButton(onClick = { showPostRevokeRecommendation = false }) {
                    Text("Maybe Later")
                }
            }
        )
    }
}

@Composable
fun DeviceItemCard(
    device: DeviceTrustManager.DeviceInfo,
    isCurrent: Boolean,
    onRevoke: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = if (device.isTrusted) MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f) 
                else MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.1f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(20.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .background(
                        if (isCurrent) MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)
                        else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f),
                        RoundedCornerShape(12.dp)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Devices, 
                    null, 
                    tint = if (isCurrent) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Spacer(Modifier.width(16.dp))
            
            Column(Modifier.weight(1f)) {
                Text(
                    text = if (isCurrent) "${device.deviceName} (This Device)" else device.deviceName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Bold
                )
                Text(
                    text = "Last seen: ${formatTimestamp(device.lastSeen)}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                if (!device.isTrusted) {
                    Text(
                        "REVOKED", 
                        color = MaterialTheme.colorScheme.error, 
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Black
                    )
                }
            }

            if (device.isTrusted && !isCurrent) {
                IconButton(onClick = onRevoke) {
                    Icon(Icons.Default.DeleteForever, "Revoke", tint = MaterialTheme.colorScheme.error)
                }
            }
        }
    }
}

private fun triggerRevocationAuth(activity: FragmentActivity, onSuccess: () -> Unit) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                onSuccess()
            }
        })

    val builder = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Revoke Device Access")
        .setSubtitle("Confirm your identity to revoke trust from this device")
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

private fun formatTimestamp(timestamp: Long): String {
    if (timestamp == 0L) return "Never"
    val sdf = SimpleDateFormat("MMM dd, yyyy HH:mm", Locale.getDefault())
    return sdf.format(Date(timestamp))
}
