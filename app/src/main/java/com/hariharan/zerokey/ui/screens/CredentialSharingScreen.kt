package com.hariharan.zerokey.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.LockOpen
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
import com.hariharan.zerokey.viewmodel.PasswordViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CredentialSharingScreen(
    viewModel: PasswordViewModel,
    onBack: () -> Unit
) {
    var recipientId by remember { mutableStateOf("") }
    var selectedCredentialId by remember { mutableStateOf<Int?>(null) }
    var showCredentialPicker by remember { mutableStateOf(false) }
    
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
                    text = "Secure Sharing",
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
                    .padding(horizontal = 24.dp),
                verticalArrangement = Arrangement.spacedBy(24.dp)
            ) {
                Text(
                    "Share encrypted credentials using ECIES (Curve25519). Recipients must provide their public key registry ID.",
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )

                OutlinedTextField(
                    value = recipientId,
                    onValueChange = { recipientId = it },
                    label = { Text("Recipient User ID") },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    leadingIcon = { Icon(Icons.Default.PersonAdd, null) }
                )

                Button(
                    onClick = { showCredentialPicker = true },
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(16.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant,
                        contentColor = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                ) {
                    val label = viewModel.passwords.find { it.id == selectedCredentialId }?.serviceName ?: "Select Credential to Share"
                    Text(label)
                }

                Text(
                    "Pending Incoming Shares",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )

                // Actual logic for incoming shares would require a new Flow in ViewModel
                Surface(
                    modifier = Modifier.fillMaxWidth().weight(1f),
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f)
                ) {
                    Box(contentAlignment = Alignment.Center) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(Icons.Default.LockOpen, null, tint = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.3f), modifier = Modifier.size(48.dp))
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "No pending incoming shares.",
                                color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.5f)
                            )
                        }
                    }
                }

                Button(
                    onClick = {
                        val senderId = "current_user_id" // In a real app, get from Auth
                        selectedCredentialId?.let { id ->
                            viewModel.shareCredential(senderId, recipientId, id)
                            Toast.makeText(context, "Secure share initialized", Toast.LENGTH_SHORT).show()
                            recipientId = ""
                            selectedCredentialId = null
                        }
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(60.dp)
                        .padding(bottom = 24.dp),
                    shape = RoundedCornerShape(20.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.onSurface,
                        contentColor = MaterialTheme.colorScheme.surface
                    ),
                    enabled = recipientId.isNotBlank() && selectedCredentialId != null
                ) {
                    Icon(Icons.Default.Share, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Initialize Secure Share", fontWeight = FontWeight.Bold)
                }
            }
        }
    }

    if (showCredentialPicker) {
        AlertDialog(
            onDismissRequest = { showCredentialPicker = false },
            title = { Text("Select Credential") },
            text = {
                LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(max = 400.dp)) {
                    items(viewModel.passwords) { item ->
                        TextButton(
                            onClick = {
                                selectedCredentialId = item.id
                                showCredentialPicker = false
                            },
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Text(item.serviceName, modifier = Modifier.fillMaxWidth())
                        }
                    }
                }
            },
            confirmButton = {
                TextButton(onClick = { showCredentialPicker = false }) { Text("Cancel") }
            }
        )
    }
}
