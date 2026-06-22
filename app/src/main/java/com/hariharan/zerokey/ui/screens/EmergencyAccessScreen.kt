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
    var showRequestDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        viewModel.refreshEmergencyRequests()
    }

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

                // --- NEW: Pending Requests for My Vault ---
                if (viewModel.pendingEmergencyRequestsForMe.isNotEmpty()) {
                    Text(
                        "Pending Access Requests",
                        style = MaterialTheme.typography.labelLarge,
                        color = MaterialTheme.colorScheme.error,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.padding(top = 16.dp)
                    )
                    
                    viewModel.pendingEmergencyRequestsForMe.forEach { req ->
                        EmergencyRequestItem(
                            userId = req.requesterUid,
                            status = "PENDING",
                            isIncoming = true,
                            approveAt = req.approveAt,
                            onAction = {
                                viewModel.approveEmergencyRequestEarly(req.requestId) { ok, msg ->
                                    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                }
                            },
                            onCancel = {
                                viewModel.cancelEmergencyRequest(req.requestId) { ok, msg ->
                                    Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
                                }
                            }
                        )
                    }
                }

                HorizontalDivider(modifier = Modifier.padding(vertical = 12.dp), color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f))

                Text(
                    "Trusted for Others",
                    style = MaterialTheme.typography.labelLarge,
                    color = MaterialTheme.colorScheme.primary,
                    fontWeight = FontWeight.Bold
                )

                if (viewModel.vaultsIAmContactFor.isNotEmpty()) {
                    viewModel.vaultsIAmContactFor.forEach { config ->
                        NominationCard(
                            ownerUid = config.ownerUid,
                            inactivityDays = config.inactivityDays,
                            onRequestAccess = {
                                viewModel.requestEmergencyAccess(context, config.ownerUid) { ok, msg ->
                                    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                                }
                            }
                        )
                    }
                }

                Surface(
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    onClick = { showRequestDialog = true }
                ) {
                    Row(
                        modifier = Modifier.fillMaxWidth().padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(Icons.Default.LockPerson, null, tint = MaterialTheme.colorScheme.primary)
                        Spacer(Modifier.width(16.dp))
                        Column(Modifier.weight(1f)) {
                            Text("Request Access", style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
                            Text("Request access to someone else's vault.", style = MaterialTheme.typography.bodySmall)
                        }
                        Icon(Icons.Default.Add, null)
                    }
                }

                // --- NEW: Active Requests I've Made ---
                viewModel.activeEmergencyRequests.forEach { req ->
                    EmergencyRequestItem(
                        userId = req.ownerUid,
                        status = req.status.name,
                        isIncoming = false,
                        approveAt = req.approveAt,
                        onAction = {
                            if (req.status == EmergencyStatus.PENDING || req.status == EmergencyStatus.GRANTED) {
                                viewModel.claimEmergencyAccess(context, req.requestId) { ok, msg ->
                                    Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                                }
                            }
                        }
                    )
                }

                Spacer(modifier = Modifier.height(32.dp))
                
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

    if (showRequestDialog) {
        var ownerUid by remember { mutableStateOf("") }
        var isRequesting by remember { mutableStateOf(false) }

        AlertDialog(
            onDismissRequest = { showRequestDialog = false },
            title = { Text("Request Emergency Access") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                    Text("Enter the User ID of the vault owner. Access will only be granted if you were nominated as their contact and the inactivity period has passed.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = ownerUid,
                        onValueChange = { ownerUid = it },
                        label = { Text("Owner User ID") },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (ownerUid.length >= 20) {
                            isRequesting = true
                            viewModel.requestEmergencyAccess(context, ownerUid.trim()) { ok, msg ->
                                isRequesting = false
                                Toast.makeText(context, msg, Toast.LENGTH_LONG).show()
                                if (ok) showRequestDialog = false
                            }
                        }
                    },
                    enabled = !isRequesting
                ) {
                    if (isRequesting) CircularProgressIndicator(Modifier.size(20.dp), color = Color.White)
                    else Text("Submit Request")
                }
            },
            dismissButton = { TextButton(onClick = { showRequestDialog = false }) { Text("Cancel") } }
        )
    }
}

@Composable
fun NominationCard(
    ownerUid: String,
    inactivityDays: Int,
    onRequestAccess: () -> Unit
) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.15f),
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text("Contact For: $ownerUid", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                Text("Wait period: $inactivityDays days", style = MaterialTheme.typography.labelSmall)
            }
            Button(
                onClick = onRequestAccess,
                shape = RoundedCornerShape(12.dp)
            ) {
                Text("Request Access")
            }
        }
    }
}

@Composable
fun EmergencyRequestItem(
    userId: String,
    status: String,
    isIncoming: Boolean,
    approveAt: Long? = null,
    onAction: () -> Unit = {},
    onCancel: () -> Unit = {}
) {
    val remainingHours = approveAt?.let { (it - System.currentTimeMillis()) / (1000 * 60 * 60) }?.coerceAtLeast(0)

    Surface(
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surface,
        tonalElevation = 2.dp,
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)
    ) {
        Row(Modifier.padding(16.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(if (isIncoming) "From: $userId" else "To: $userId", style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                Text(
                    text = when {
                        status == "GRANTED" -> "Access Granted"
                        remainingHours != null && remainingHours > 0 -> "Ready in $remainingHours hours"
                        remainingHours != null -> "Ready to claim"
                        else -> "Status: $status"
                    },
                    style = MaterialTheme.typography.labelSmall,
                    color = if (status == "GRANTED") Color(0xFF4CAF50) else MaterialTheme.colorScheme.primary
                )
            }
            
            if (isIncoming) {
                IconButton(onClick = onCancel) { Icon(Icons.Default.Close, null, tint = MaterialTheme.colorScheme.error) }
                Button(onClick = onAction) { Text("Approve") }
            } else {
                if (status == "PENDING" || status == "GRANTED") {
                    Button(
                        onClick = onAction,
                        enabled = remainingHours == null || remainingHours <= 0 || status == "GRANTED"
                    ) {
                        Text(if (status == "GRANTED") "Unlock" else "Claim")
                    }
                }
            }
        }
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
