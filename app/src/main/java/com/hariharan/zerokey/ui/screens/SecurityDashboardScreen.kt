package com.hariharan.zerokey.ui.screens

import androidx.compose.animation.core.*
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hariharan.zerokey.core.crypto.EncryptionManager
import com.hariharan.zerokey.core.crypto.KeySecurityLevel
import com.hariharan.zerokey.security.SecurityHardening
import com.hariharan.zerokey.securityanalytics.*
import com.hariharan.zerokey.viewmodel.PasswordViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityDashboardScreen(
    viewModel: PasswordViewModel,
    onBack: () -> Unit,
    onFixCredential: (Int) -> Unit = {}
) {
    val report = viewModel.securityReport
    val surfaceColor = MaterialTheme.colorScheme.surface

    LaunchedEffect(Unit) {
        viewModel.ensureSecurityReport()
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
                    text = "Security Intelligence",
                    style = MaterialTheme.typography.headlineSmall.copy(
                        fontWeight = FontWeight.Black,
                        letterSpacing = (-1).sp
                    ),
                    modifier = Modifier.padding(start = 8.dp)
                )
            }

            if (report == null) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            } else {
                DashboardContent(viewModel, report, Modifier.fillMaxSize(), onFixCredential)
            }
        }
    }
}

@Composable
private fun DashboardContent(viewModel: PasswordViewModel, report: VaultSecurityReport, modifier: Modifier, onFixCredential: (Int) -> Unit) {
    val score = report.securityScore
    val grade = when {
        score >= 90 -> SecurityGrade.EXCELLENT
        score >= 75 -> SecurityGrade.GOOD
        score >= 50 -> SecurityGrade.FAIR
        score >= 25 -> SecurityGrade.POOR
        else -> SecurityGrade.CRITICAL
    }

    LazyColumn(
        modifier = modifier,
        contentPadding = PaddingValues(24.dp),
        verticalArrangement = Arrangement.spacedBy(24.dp)
    ) {
        item { SecurityScoreCard(score, grade) }

        item {
            HardwareSecurityCard(viewModel)
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatCard(
                    modifier = Modifier.weight(1f),
                    label = "Weak",
                    count = report.weakPasswords.size,
                    icon = Icons.Default.Warning,
                    color = Color(0xFFF39C12)
                )
                StatCard(
                    modifier = Modifier.weight(1f),
                    label = "Reused",
                    count = report.duplicateGroups.sumOf { it.credentialIds.size - 1 },
                    icon = Icons.Default.ContentCopy,
                    color = Color(0xFFE67E22)
                )
                StatCard(
                    modifier = Modifier.weight(1f),
                    label = "Breached",
                    count = report.breachedCredentials.size,
                    icon = Icons.Default.GppBad,
                    color = Color(0xFFE74C3C)
                )
            }
        }

        item {
            AccessibilityAuditCard()
        }

        if (report.breachedCredentials.isNotEmpty()) {
            item { SectionHeader("Breach Alerts", Icons.Default.GppBad, Color(0xFFE74C3C)) }
            items(report.breachedCredentials) { item ->
                BreachAlertCard(item, onFixCredential)
            }
        }

        if (report.weakPasswords.isNotEmpty()) {
            item { SectionHeader("Weak Passwords", Icons.Default.Warning, Color(0xFFF39C12)) }
            items(report.weakPasswords) { item ->
                WeakPasswordCard(item, onFixCredential)
            }
        }

        if (report.duplicateGroups.isNotEmpty()) {
            item { SectionHeader("Reused Passwords", Icons.Default.ContentCopy, Color(0xFFE67E22)) }
            items(report.duplicateGroups) { group ->
                DuplicateGroupCard(group, onFixCredential)
            }
        }
    }
}

@Composable
private fun HardwareSecurityCard(viewModel: PasswordViewModel) {
    val securityLevel = remember { viewModel.keySecurityLevel }
    
    val (label, description, color, icon) = when (securityLevel) {
        KeySecurityLevel.STRONGBOX -> Triple(
            "StrongBox Verified",
            "Maximum Security: Root key is protected by a dedicated hardware secure element.",
            Color(0xFF4CAF50)
        ).let { it.copy(fourth = Icons.Default.Shield) }
        
        KeySecurityLevel.TEE -> Triple(
            "TEE Verified",
            "High Security: Root key is stored in a Trusted Execution Environment (isolated from Android).",
            Color(0xFF2196F3)
        ).let { it.copy(fourth = Icons.Default.Security) }
        
        KeySecurityLevel.SOFTWARE -> Triple(
            "Software Emulated",
            "Limited Security: No secure hardware detected for root key. Rooted devices are at risk.",
            Color(0xFFE74C3C)
        ).let { it.copy(fourth = Icons.Default.Memory) }
        
        else -> Triple(
            "Status Unknown",
            "Unable to verify hardware security status of the root key.",
            Color(0xFF7F8C8D)
        ).let { it.copy(fourth = Icons.Default.Warning) }
    }

    Surface(
        shape = RoundedCornerShape(28.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon as androidx.compose.ui.graphics.vector.ImageVector,
                contentDescription = null,
                tint = color as Color,
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.width(20.dp))
            Column {
                Text(
                    text = label as String,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = description as String,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f)
                )
            }
        }
    }
}

private fun <A, B, C> Triple<A, B, C>.copy(fourth: Any): Quadruple<A, B, C, Any> = Quadruple(first, second, third, fourth)
data class Quadruple<A, B, C, D>(val first: A, val second: B, val third: C, val fourth: D)

@Composable
private fun AccessibilityAuditCard() {
    val context = LocalContext.current
    val riskLevel = remember { SecurityHardening.getAccessibilityRiskLevel(context) }
    val services = remember { SecurityHardening.getHighRiskServiceNames(context) }

    val (label, color, description) = when (riskLevel) {
        SecurityHardening.RiskLevel.HIGH -> Triple(
            "Accessibility Warning",
            Color(0xFFE74C3C),
            "High-risk services active: ${services.joinToString(", ")}. These apps can read your screen content."
        )
        SecurityHardening.RiskLevel.MEDIUM -> Triple(
            "Accessibility Audit",
            Color(0xFFF39C12),
            "Third-party services enabled. Ensure you trust these apps to prevent data capture."
        )
        SecurityHardening.RiskLevel.LOW -> Triple(
            "Accessibility Safe",
            Color(0xFF4CAF50),
            "No high-risk third-party accessibility services detected."
        )
        else -> Triple(
            "Status Unknown",
            Color(0xFF7F8C8D),
            "Unable to audit accessibility services."
        )
    }

    Surface(
        shape = RoundedCornerShape(28.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier.padding(24.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = Icons.Default.Visibility,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.width(20.dp))
            Column {
                Text(
                    text = label,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f)
                )
            }
        }
    }
}

@Composable
private fun SecurityScoreCard(score: Int, grade: SecurityGrade) {
    val animatedScore by animateIntAsState(
        targetValue = score,
        animationSpec = tween(durationMillis = 1200, easing = FastOutSlowInEasing), label = ""
    )
    val gradeColor = Color(android.graphics.Color.parseColor(grade.colorHex))

    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(32.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column {
                Text(
                    text = "Vault Security Score",
                    style = MaterialTheme.typography.titleMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    text = grade.label,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold,
                    color = gradeColor
                )
                Spacer(Modifier.height(16.dp))
                LinearProgressIndicator(
                    progress = { animatedScore / 100f },
                    modifier = Modifier
                        .width(140.dp)
                        .height(8.dp)
                        .clip(CircleShape),
                    color = gradeColor,
                    trackColor = gradeColor.copy(alpha = 0.2f)
                )
            }

            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.size(90.dp)
            ) {
                Canvas(modifier = Modifier.fillMaxSize()) {
                    val stroke = Stroke(width = 8.dp.toPx(), cap = StrokeCap.Round)
                    drawArc(
                        color = gradeColor.copy(alpha = 0.1f),
                        startAngle = -90f, sweepAngle = 360f,
                        useCenter = false, style = stroke
                    )
                    drawArc(
                        color = gradeColor,
                        startAngle = -90f,
                        sweepAngle = 360f * (animatedScore / 100f),
                        useCenter = false, style = stroke
                    )
                }
                Text(
                    text = "$animatedScore",
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Black,
                    color = gradeColor
                )
            }
        }
    }
}

@Composable
private fun StatCard(
    modifier: Modifier,
    label: String,
    count: Int,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color
) {
    Surface(
        modifier = modifier,
        shape = RoundedCornerShape(20.dp),
        color = color.copy(alpha = 0.1f)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, contentDescription = label, tint = color, modifier = Modifier.size(24.dp))
            Spacer(Modifier.height(8.dp))
            Text(
                text = "$count",
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelSmall,
                color = color
            )
        }
    }
}

@Composable
private fun SectionHeader(
    title: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color
) {
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(icon, contentDescription = null, tint = color, modifier = Modifier.size(20.dp))
        Spacer(Modifier.width(8.dp))
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
    }
}

@Composable
private fun BreachAlertCard(item: BreachedItem, onFix: (Int) -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = Color(0xFFE74C3C).copy(alpha = 0.08f),
        border = BorderStroke(1.dp, Color(0xFFE74C3C).copy(alpha = 0.2f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.GppBad,
                contentDescription = null,
                tint = Color(0xFFE74C3C),
                modifier = Modifier.size(32.dp)
            )
            Spacer(Modifier.width(16.dp))
            Column {
                Text(item.domain, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                Text(
                    "Found in: ${item.breachSource}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { onFix(item.credentialId) }) { Text("Fix", color = Color(0xFFE74C3C)) }
        }
    }
}

@Composable
private fun WeakPasswordCard(item: WeakPasswordItem, onFix: (Int) -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
        border = BorderStroke(1.dp, Color(0xFFF39C12).copy(alpha = 0.3f))
    ) {
        Row(
            modifier = Modifier.padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Default.Warning, contentDescription = null, tint = Color(0xFFF39C12))
            Spacer(Modifier.width(16.dp))
            Column(Modifier.weight(1f)) {
                Text(item.domain, style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
                Text(item.reason, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            TextButton(onClick = { onFix(item.credentialId) }) { Text("Change") }
        }
    }
}

@Composable
private fun DuplicateGroupCard(group: DuplicateGroup, onFix: (Int) -> Unit) {
    Surface(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(20.dp),
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.2f),
        border = BorderStroke(1.dp, Color(0xFFE67E22).copy(alpha = 0.3f))
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Default.ContentCopy, contentDescription = null, tint = Color(0xFFE67E22))
                Spacer(Modifier.width(8.dp))
                Text(
                    "${group.credentialIds.size} accounts share a password",
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            Spacer(Modifier.height(8.dp))
            group.domains.forEachIndexed { index, domain ->
                if (index < 3) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            "• $domain",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(start = 8.dp)
                        )
                        TextButton(
                            onClick = { onFix(group.credentialIds[index]) },
                            contentPadding = PaddingValues(0.dp),
                            modifier = Modifier.height(24.dp)
                        ) {
                            Text("Fix", style = MaterialTheme.typography.labelSmall)
                        }
                    }
                }
            }
            if (group.domains.size > 3) {
                Text(
                    "• +${group.domains.size - 3} more",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.6f),
                    modifier = Modifier.padding(start = 8.dp)
                )
            }
        }
    }
}
