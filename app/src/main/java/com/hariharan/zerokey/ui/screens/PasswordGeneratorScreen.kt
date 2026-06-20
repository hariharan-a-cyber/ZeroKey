package com.hariharan.zerokey.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Refresh
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
import com.hariharan.zerokey.utils.PasswordUtils
import com.hariharan.zerokey.utils.SecureClipboard
import android.content.ClipboardManager
import android.content.Context
import android.content.ClipData

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PasswordGeneratorScreen(
    onBack: () -> Unit,
    onUsePassword: (String) -> Unit = {}
) {
    var length by remember { mutableFloatStateOf(20f) }
    var includeUppercase by remember { mutableStateOf(true) }
    var includeNumbers by remember { mutableStateOf(true) }
    var includeSymbols by remember { mutableStateOf(true) }
    
    var generatedPassword by remember { 
        mutableStateOf(PasswordUtils.generatePassword(length.toInt(), includeUppercase, includeNumbers, includeSymbols)) 
    }

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
                    text = "Generator",
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
                // Password Display Card
                Surface(
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(240.dp), // Increased further to 240dp for absolute stability
                    shape = RoundedCornerShape(24.dp),
                    color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
                ) {
                    Column(
                        modifier = Modifier.padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        // Use a fixed-height Box for the text to prevent it from pushing buttons
                        Box(
                            modifier = Modifier
                                .weight(1f)
                                .fillMaxWidth(),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                text = generatedPassword,
                                style = MaterialTheme.typography.headlineMedium.copy(
                                    fontFamily = androidx.compose.ui.text.font.FontFamily.Monospace,
                                    fontWeight = FontWeight.Bold,
                                    letterSpacing = 1.sp,
                                    fontSize = if (generatedPassword.length > 32) 18.sp else 24.sp
                                ),
                                color = MaterialTheme.colorScheme.primary,
                                textAlign = androidx.compose.ui.text.style.TextAlign.Center,
                                modifier = Modifier.fillMaxWidth()
                            )
                        }
                        
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceEvenly
                        ) {
                            IconButton(onClick = { 
                                generatedPassword = PasswordUtils.generatePassword(length.toInt(), includeUppercase, includeNumbers, includeSymbols) 
                            }) {
                                Icon(Icons.Default.Refresh, "Regenerate")
                            }
                            IconButton(onClick = { 
                                SecureClipboard.copy(context, generatedPassword)
                                Toast.makeText(context, "Copied to clipboard", Toast.LENGTH_SHORT).show()
                            }) {
                                Icon(Icons.Default.ContentCopy, "Copy")
                            }
                        }
                    }
                }

                // Controls
                Column(verticalArrangement = Arrangement.spacedBy(16.dp)) {
                    Text(
                        text = "Length: ${length.toInt()}",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Slider(
                        value = length,
                        onValueChange = { 
                            length = it
                            generatedPassword = PasswordUtils.generatePassword(length.toInt(), includeUppercase, includeNumbers, includeSymbols)
                        },
                        valueRange = 15f..64f, // Updated Range: 15 to 64
                        steps = 49 // (64 - 15 = 49 steps)
                    )

                    GeneratorToggle(
                        label = "Uppercase (A-Z)",
                        checked = includeUppercase,
                        onCheckedChange = { 
                            includeUppercase = it
                            generatedPassword = PasswordUtils.generatePassword(length.toInt(), includeUppercase, includeNumbers, includeSymbols)
                        }
                    )
                    GeneratorToggle(
                        label = "Numbers (0-9)",
                        checked = includeNumbers,
                        onCheckedChange = { 
                            includeNumbers = it
                            generatedPassword = PasswordUtils.generatePassword(length.toInt(), includeUppercase, includeNumbers, includeSymbols)
                        }
                    )
                    GeneratorToggle(
                        label = "Symbols (!@#$)",
                        checked = includeSymbols,
                        onCheckedChange = { 
                            includeSymbols = it
                            generatedPassword = PasswordUtils.generatePassword(length.toInt(), includeUppercase, includeNumbers, includeSymbols)
                        }
                    )
                }

                Spacer(modifier = Modifier.weight(1f))

                Button(
                    onClick = { onUsePassword(generatedPassword) },
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(60.dp)
                        .padding(bottom = 24.dp),
                    shape = RoundedCornerShape(20.dp),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.onSurface,
                        contentColor = MaterialTheme.colorScheme.surface
                    )
                ) {
                    Text("Use Password", fontWeight = FontWeight.Bold)
                }
            }
        }
    }
}

@Composable
fun GeneratorToggle(label: String, checked: Boolean, onCheckedChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween
    ) {
        Text(text = label, style = MaterialTheme.typography.bodyLarge)
        Switch(checked = checked, onCheckedChange = onCheckedChange)
    }
}
