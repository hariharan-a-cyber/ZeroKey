package com.hariharan.zerokey.security

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.service.autofill.Dataset
import android.service.autofill.FillResponse
import android.view.autofill.AutofillId
import android.view.autofill.AutofillManager
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import android.widget.Toast
import androidx.activity.compose.setContent
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Fingerprint
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.hariharan.zerokey.R
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.ui.theme.ZeroKeyTheme
import com.hariharan.zerokey.core.security.MasterPasswordManager
import com.hariharan.zerokey.core.security.AuthAttemptManager
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import javax.inject.Inject

@AndroidEntryPoint
class AutofillUnlockActivity : FragmentActivity() {

    @Inject lateinit var masterPasswordManager: MasterPasswordManager
    @Inject lateinit var vaultRepository: PasswordRepository
    @Inject lateinit var authAttemptManager: AuthAttemptManager

    private var usernameId: AutofillId? = null
    private var passwordId: AutofillId? = null
    private var verifiedDomain: String? = null
    private var isUnverified: Boolean = false
    private var isManualSearch: Boolean = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        window.setFlags(
            android.view.WindowManager.LayoutParams.FLAG_SECURE,
            android.view.WindowManager.LayoutParams.FLAG_SECURE
        )

        usernameId = intent.getParcelableExtra("username_id")
        passwordId = intent.getParcelableExtra("password_id")
        verifiedDomain = intent.getStringExtra("verified_domain")
        isUnverified = intent.getBooleanExtra("is_unverified", false)
        isManualSearch = intent.getBooleanExtra("manual_search", false)

        setContent {
            ZeroKeyTheme {
                AutofillUnlockScreen(
                    masterPasswordManager = masterPasswordManager,
                    vaultRepository = vaultRepository,
                    authAttemptManager = authAttemptManager,
                    isManual = isManualSearch,
                    onUnlocked = {
                        if (isManualSearch) {
                            // Handled by state
                        } else {
                            finalizeAutofill()
                        }
                    },
                    onSearchComplete = { selectedItem ->
                        finalizeManualAutofill(selectedItem)
                    },
                    onCancel = { finish() }
                )
            }
        }
    }

    private fun finalizeAutofill() {
        val domain = verifiedDomain ?: ""
        val repository = vaultRepository

        CoroutineScope(Dispatchers.IO).launch {
            val normalizedDomain = extractRegistrableDomain(domain)
            val credentials = if (normalizedDomain.isEmpty()) {
                emptyList<PasswordItem>()
            } else {
                repository.getPasswords().filter { cred ->
                    extractRegistrableDomain(cred.serviceName)
                        .equals(normalizedDomain, ignoreCase = true)
                }
            }

            val builder = FillResponse.Builder()
            credentials.take(10).forEach { cred ->
                val dataset = Dataset.Builder().apply {
                    usernameId?.let {
                        setValue(it, AutofillValue.forText(cred.username),
                            createPresentation(cred.serviceName, cred.username))
                    }
                    passwordId?.let {
                        setValue(it, AutofillValue.forText(cred.password),
                            createPresentation(cred.serviceName, "••••••••"))
                    }
                }.build()
                builder.addDataset(dataset)
            }
            withContext(Dispatchers.Main) {
                val reply = Intent().apply {
                    putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, builder.build())
                }
                setResult(RESULT_OK, reply)
                finish()
            }
        }
    }

    private fun createPresentation(service: String, username: String): RemoteViews {
        val label = if (isUnverified) "⚠️ UNVERIFIED: $username" else "$service: $username"
        return RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, label)
        }
    }

    private fun extractRegistrableDomain(host: String): String {
        val parts = host.lowercase().split(".")
        if (parts.size < 2) return host
        val lastTwo = "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
        val multiPartTlds = listOf("co.uk", "com.br", "org.uk", "net.uk", "com.au", "co.jp", "ac.uk")
        return if (multiPartTlds.contains(lastTwo) && parts.size >= 3) {
            "${parts[parts.size - 3]}.$lastTwo"
        } else {
            lastTwo
        }
    }

    private fun finalizeManualAutofill(item: PasswordItem) {
        val response = FillResponse.Builder()
        val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
            setTextViewText(android.R.id.text1, item.username)
        }
        val datasetBuilder = Dataset.Builder(presentation)
        
        usernameId?.let { datasetBuilder.setValue(it, AutofillValue.forText(item.username)) }
        passwordId?.let { datasetBuilder.setValue(it, AutofillValue.forText(item.password)) }
        
        response.addDataset(datasetBuilder.build())

        val resultIntent = Intent()
        resultIntent.putExtra(AutofillManager.EXTRA_AUTHENTICATION_RESULT, response.build())
        setResult(RESULT_OK, resultIntent)
        finish()
    }
}

@Composable
fun AutofillUnlockScreen(
    masterPasswordManager: MasterPasswordManager,
    vaultRepository: PasswordRepository,
    authAttemptManager: AuthAttemptManager,
    isManual: Boolean = false,
    onUnlocked: () -> Unit,
    onSearchComplete: (PasswordItem) -> Unit = {},
    onCancel: () -> Unit
) {
    val context = LocalContext.current as FragmentActivity
    var showMasterPassword by remember { mutableStateOf(false) }
    var password by remember { mutableStateOf("") }
    var isError by remember { mutableStateOf(false) }
    
    var isAuthenticated by remember { mutableStateOf(false) }
    
    if (isAuthenticated && isManual) {
        ManualSearchScreen(vaultRepository, onSearchComplete, onCancel)
        return
    }

    Surface(
        modifier = Modifier.fillMaxSize(),
        color = MaterialTheme.colorScheme.surface
    ) {
        Column(
            modifier = Modifier.padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Icon(
                Icons.Default.Lock,
                contentDescription = null,
                modifier = Modifier.size(64.dp),
                tint = MaterialTheme.colorScheme.primary
            )
            Spacer(Modifier.height(24.dp))
            Text(
                if (isManual) "Unlock ZeroKey to Search" else "Unlock ZeroKey to Autofill",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center
            )
            Spacer(Modifier.height(48.dp))

            if (!showMasterPassword) {
                Button(
                    onClick = { 
                        triggerBiometric(context, masterPasswordManager) {
                            isAuthenticated = true
                            onUnlocked()
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Icon(Icons.Default.Fingerprint, null)
                    Spacer(Modifier.width(8.dp))
                    Text("Unlock with Biometrics")
                }
                
                TextButton(
                    onClick = { showMasterPassword = true },
                    modifier = Modifier.padding(top = 16.dp)
                ) {
                    Text("Use Master Password instead")
                }
            } else {
                OutlinedTextField(
                    value = password,
                    onValueChange = { 
                        password = it
                        isError = false
                    },
                    label = { Text("Master Password") },
                    isError = isError,
                    modifier = Modifier.fillMaxWidth(),
                    visualTransformation = androidx.compose.ui.text.input.PasswordVisualTransformation(),
                    shape = RoundedCornerShape(16.dp)
                )
                if (isError) {
                    Text("Incorrect password", color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.labelSmall)
                }
                Spacer(Modifier.height(24.dp))
                Button(
                    onClick = {
                        if (authAttemptManager.isLockedOut()) {
                            val rem = authAttemptManager.getRemainingLockoutTime() / 1000
                            Toast.makeText(context, "Too many attempts. Try again in ${rem}s.", Toast.LENGTH_LONG).show()
                            return@Button
                        }
                        try {
                            masterPasswordManager.unlockVault(context, password.toCharArray())
                            masterPasswordManager.authorizeAutofill()
                            authAttemptManager.resetAttempts()
                            isAuthenticated = true
                            onUnlocked()
                        } catch (e: Exception) {
                            authAttemptManager.recordFailedAttempt("autofill-unlock")
                            isError = true
                        }
                    },
                    modifier = Modifier.fillMaxWidth().height(56.dp),
                    shape = RoundedCornerShape(16.dp),
                    enabled = password.length >= 6
                ) {
                    Text("Unlock")
                }
                TextButton(onClick = { showMasterPassword = false }) {
                    Text("Back to Biometrics")
                }
            }
            
            Spacer(Modifier.height(16.dp))
            TextButton(onClick = onCancel) {
                Text("Cancel", color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }

    LaunchedEffect(Unit) {
        if (!showMasterPassword && !isAuthenticated) {
            triggerBiometric(context, masterPasswordManager) {
                isAuthenticated = true
                onUnlocked()
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ManualSearchScreen(repository: PasswordRepository, onSelect: (PasswordItem) -> Unit, onCancel: () -> Unit) {
    var query by remember { mutableStateOf("") }
    var items by remember { mutableStateOf<List<PasswordItem>>(emptyList()) }
    
    LaunchedEffect(Unit) {
        withContext(Dispatchers.IO) {
            items = repository.getPasswords()
        }
    }
    
    val filteredItems = remember(query, items) {
        if (query.isBlank()) items
        else items.filter { it.serviceName.contains(query, ignoreCase = true) || it.username.contains(query, ignoreCase = true) }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.surface) {
        Column(modifier = Modifier.fillMaxSize()) {
            CenterAlignedTopAppBar(
                title = { Text("Search Vault") },
                navigationIcon = {
                    IconButton(onClick = onCancel) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Back")
                    }
                }
            )
            
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                modifier = Modifier.fillMaxWidth().padding(16.dp),
                placeholder = { Text("Search service or username...") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                shape = RoundedCornerShape(16.dp),
                singleLine = true
            )
            
            LazyColumn(modifier = Modifier.weight(1f)) {
                items(filteredItems) { item ->
                    ListItem(
                        headlineContent = { Text(item.serviceName, fontWeight = FontWeight.Bold) },
                        supportingContent = { Text(item.username) },
                        modifier = Modifier.clickable { onSelect(item) }
                    )
                    HorizontalDivider(modifier = Modifier.padding(horizontal = 16.dp), thickness = 0.5.dp, color = MaterialTheme.colorScheme.outlineVariant)
                }
            }
        }
    }
}

private fun triggerBiometric(activity: FragmentActivity, masterPasswordManager: MasterPasswordManager, onSuccess: () -> Unit) {
    val executor = ContextCompat.getMainExecutor(activity)
    val biometricPrompt = BiometricPrompt(activity, executor,
        object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                super.onAuthenticationSucceeded(result)
                if (masterPasswordManager.isUnlocked()) {
                    masterPasswordManager.authorizeAutofill()
                    onSuccess()
                } else {
                    Toast.makeText(activity, "Vault locked. Enter your master password.", Toast.LENGTH_SHORT).show()
                }
            }
        })

    val builder = BiometricPrompt.PromptInfo.Builder()
        .setTitle("ZeroKey Autofill")
        .setSubtitle("Authenticate to access your vault")
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
