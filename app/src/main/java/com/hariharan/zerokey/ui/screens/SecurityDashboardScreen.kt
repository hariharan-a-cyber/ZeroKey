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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.hariharan.zerokey.securityanalytics.*
import com.hariharan.zerokey.viewmodel.PasswordViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityDashboardScreen(
    viewModel: PasswordViewModel,
    onBack: () -> Unit
) {
    val report = viewModel.securityReport
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
                DashboardContent(report, Modifier.fillMaxSize())
            }
        }
    }
}

@Composable
private fun DashboardContent(report: VaultSecurityReport, modifier: Modifier) {
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

        if (report.breachedCredentials.isNotEmpty()) {
            item { SectionHeader("Breach Alerts", Icons.Default.GppBad, Color(0xFFE74C3C)) }
            items(report.breachedCredentials) { item ->
                BreachAlertCard(item)
            }
        }

        if (report.weakPasswords.isNotEmpty()) {
            item { SectionHeader("Weak Passwords", Icons.Default.Warning, Color(0xFFF39C12)) }
            items(report.weakPasswords) { item ->
                WeakPasswordCard(item)
            }
        }

        if (report.duplicateGroups.isNotEmpty()) {
            item { SectionHeader("Reused Passwords", Icons.Default.ContentCopy, Color(0xFFE67E22)) }
            items(report.duplicateGroups) { group ->
                DuplicateGroupCard(group)
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
private fun BreachAlertCard(item: BreachedItem) {
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
            TextButton(onClick = {}) { Text("Fix", color = Color(0xFFE74C3C)) }
        }
    }
}

@Composable
private fun WeakPasswordCard(item: WeakPasswordItem) {
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
            TextButton(onClick = {}) { Text("Change") }
        }
    }
}

@Composable
private fun DuplicateGroupCard(group: DuplicateGroup) {
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
            group.domains.take(3).forEach { domain ->
                Text(
                    "• $domain",
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(start = 8.dp)
                )
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
