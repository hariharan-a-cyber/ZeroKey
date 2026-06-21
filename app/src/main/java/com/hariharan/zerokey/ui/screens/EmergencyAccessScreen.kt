package com.hariharan.zerokey.ui.screens

import android.widget.Toast
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
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
import com.hariharan.zerokey.emergency.EmergencyStatus
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EmergencyAccessScreen(
    viewModel: PasswordViewModel,
    onBack: () -> Unit
) {
    val context = LocalContext.current
    val surfaceColor = MaterialTheme.colorScheme.surface
    
    val config = viewModel.emergencyConfig
    val isConfigured = config != null
    var showSetupDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { Text("Emergency Access", style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)) },
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
                // Info Card
                Surface(
                    shape = RoundedCornerShape(28.dp),
                    color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(Modifier.padding(24.dp)) {
                        Icon(Icons.Default.HealthAndSafety, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(32.dp))
                        Spacer(Modifier.height(16.dp))
                        Text(
                            "What is Emergency Access?",
                            style = MaterialTheme.typography.titleLarge,
                            fontWeight = FontWeight.Black
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "Grant a trusted contact access to your vault if you are inactive for a certain period. Access is granted after a 48-hour security window during which you can cancel the request.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }

                Text(
                    "Your Configuration",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold,
                    modifier = Modifier.padding(top = 8.dp)
                )

                if (!isConfigured) {
                    Surface(
                        shape = RoundedCornerShape(24.dp),
                        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                        onClick = { showSetupDialog = true }
                    ) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(20.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(Icons.Default.AddModerator, null, tint = MaterialTheme.colorScheme.primary)
                            Spacer(Modifier.width(16.dp))
                            Column(Modifier.weight(1f)) {
                                Text("Setup Trusted Contact", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                                Text("No emergency contact configured yet.", style = MaterialTheme.typography.bodySmall)
                            }
                            Icon(Icons.Default.ChevronRight, null)
                        }
                    }
                } else {
                    ConfiguredContactCard(
                        email = config?.contactEmail ?: "Unknown",
                        days = config?.inactivityDays ?: 7,
                        onRemove = { /* TODO: Implement revocation */ }
                    )
                }

                Spacer(modifier = Modifier.weight(1f))
                
                Text(
                    "SECURITY NOTE: This feature uses cryptographic signing. Your trusted contact can only decrypt your vault with your permission or after the inactivity timer expires. You can revoke this at any time.",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f),
                    modifier = Modifier.padding(horizontal = 8.dp)
                )
            }
        }
    }

    if (showSetupDialog) {
        var tempUid by remember { mutableStateOf("") }
        var tempEmail by remember { mutableStateOf("") }
        var tempDays by remember { mutableStateOf(7) }
        
        AlertDialog(
            onDismissRequest = { showSetupDialog = false },
            title = { Text("Setup Trusted Contact") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    OutlinedTextField(
                        value = tempUid,
                        onValueChange = { tempUid = it },
                        label = { Text("Contact User ID") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    OutlinedTextField(
                        value = tempEmail,
                        onValueChange = { tempEmail = it },
                        label = { Text("Contact Email (for notifications)") },
                        modifier = Modifier.fillMaxWidth(),
                        singleLine = true
                    )
                    
                    Column {
                        Text("Inactivity Period: $tempDays days", style = MaterialTheme.typography.labelMedium)
                        Slider(
                            value = tempDays.toFloat(),
                            onValueChange = { tempDays = it.toInt() },
                            valueRange = 1f..30f,
                            steps = 29
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (tempUid.length >= 20 && tempEmail.contains("@")) {
                            viewModel.setupEmergencyAccess(context, tempUid, tempEmail, tempDays) { ok, msg ->
                                Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                if (ok) showSetupDialog = false
                            }
                        } else {
                            Toast.makeText(context, "Enter a valid UID and email", Toast.LENGTH_SHORT).show()
                        }
                    },
                    enabled = !viewModel.isConfiguringEmergency
                ) {
                    if (viewModel.isConfiguringEmergency) {
                        CircularProgressIndicator(Modifier.size(20.dp), color = Color.White)
                    } else {
                        Text("Enable Emergency Access")
                    }
                }
            },
            dismissButton = {
                TextButton(onClick = { showSetupDialog = false }) { Text("Cancel") }
            }
        )
    }
}

@Composable
fun ConfiguredContactCard(email: String, days: Int, onRemove: () -> Unit) {
    Surface(
        shape = RoundedCornerShape(24.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(Modifier.padding(20.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.VerifiedUser, null, tint = Color(0xFF4CAF50))
                Spacer(Modifier.width(16.dp))
                Column(Modifier.weight(1f)) {
                    Text(email, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                    Text("Trusted Contact", style = MaterialTheme.typography.bodySmall)
                }
                IconButton(onClick = onRemove) {
                    Icon(Icons.Default.Delete, null, tint = MaterialTheme.colorScheme.error)
                }
            }
            
            HorizontalDivider(
                modifier = Modifier.padding(vertical = 12.dp),
                thickness = 1.dp,
                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.1f)
            )
            
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.Timer, null, tint = MaterialTheme.colorScheme.primary, modifier = Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text("Wait period: $days days inactivity", style = MaterialTheme.typography.bodySmall)
            }
        }
    }
}
