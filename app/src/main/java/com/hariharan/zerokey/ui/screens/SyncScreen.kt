package com.hariharan.zerokey.ui.screens

import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hariharan.zerokey.viewmodel.SyncViewModel
import java.text.SimpleDateFormat
import java.util.*

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SyncScreen(
    viewModel: SyncViewModel,
    onBack: () -> Unit,
    userId: String
) {
    val syncState by viewModel.syncState.collectAsState()
    val surfaceColor = MaterialTheme.colorScheme.surface

    Scaffold(
        topBar = {
            CenterAlignedTopAppBar(
                title = { 
                    Text(
                        "Cloud Sync", 
                        style = MaterialTheme.typography.titleMedium.copy(fontWeight = FontWeight.Bold)
                    ) 
                },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Back")
                    }
                },
                colors = TopAppBarDefaults.centerAlignedTopAppBarColors(
                    containerColor = Color.Transparent
                )
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
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(24.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Sync Status Icon
                Box(
                    modifier = Modifier
                        .size(120.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.1f)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        imageVector = if (syncState is SyncViewModel.SyncStatus.Error) Icons.Default.SyncProblem else Icons.Default.CloudSync,
                        contentDescription = null,
                        modifier = Modifier.size(60.dp),
                        tint = if (syncState is SyncViewModel.SyncStatus.Error) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary
                    )
                }

                Spacer(modifier = Modifier.height(32.dp))

                Text(
                    text = when (syncState) {
                        is SyncViewModel.SyncStatus.Idle -> "Your vault is local-only"
                        is SyncViewModel.SyncStatus.Syncing -> "Syncing encrypted vault..."
                        is SyncViewModel.SyncStatus.Success -> "Vault is up to date"
                        is SyncViewModel.SyncStatus.Error -> "Sync failed"
                    },
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Black
                )

                Spacer(modifier = Modifier.height(8.dp))

                Text(
                    text = when (val state = syncState) {
                        is SyncViewModel.SyncStatus.Success -> "Last synced: ${formatTimestamp(state.lastSync)}"
                        is SyncViewModel.SyncStatus.Error -> state.message
                        else -> "Keep your credentials safe across all your devices."
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = androidx.compose.ui.text.style.TextAlign.Center
                )

                Spacer(modifier = Modifier.weight(1f))

                // Sync Actions Card
                Surface(
                    shape = RoundedCornerShape(28.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Column(modifier = Modifier.padding(24.dp)) {
                        SyncFeatureItem(
                            icon = Icons.Default.EnhancedEncryption,
                            title = "Zero-Knowledge",
                            subtitle = "Encryption happens locally. We never see your data."
                        )
                        Spacer(modifier = Modifier.height(20.dp))
                        SyncFeatureItem(
                            icon = Icons.Default.Devices,
                            title = "Cross-Device",
                            subtitle = "Access your passwords on any authorized device."
                        )
                    }
                }

                Spacer(modifier = Modifier.height(24.dp))

                Button(
                    onClick = { viewModel.performSync(userId) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(64.dp),
                    shape = RoundedCornerShape(20.dp),
                    enabled = syncState !is SyncViewModel.SyncStatus.Syncing,
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.onSurface,
                        contentColor = MaterialTheme.colorScheme.surface
                    )
                ) {
                    if (syncState is SyncViewModel.SyncStatus.Syncing) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(24.dp),
                            color = MaterialTheme.colorScheme.surface,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text(
                            "Sync Now",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.Bold
                        )
                    }
                }
            }
        }
    }
}

@Composable
fun SyncFeatureItem(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    subtitle: String
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            modifier = Modifier
                .size(40.dp)
                .clip(CircleShape)
                .background(MaterialTheme.colorScheme.onSurface.copy(alpha = 0.05f)),
            contentAlignment = Alignment.Center
        ) {
            Icon(icon, null, modifier = Modifier.size(20.dp))
        }
        Spacer(modifier = Modifier.width(16.dp))
        Column {
            Text(title, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Bold)
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
    }
}

private fun formatTimestamp(timestamp: Long): String {
    val sdf = SimpleDateFormat("MMM dd, HH:mm", Locale.getDefault())
    return sdf.format(Date(timestamp))
}
