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
import com.hariharan.zerokey.core.database.PasswordDatabase
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.ui.theme.ZeroKeyTheme
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

import com.hariharan.zerokey.core.security.MasterPasswordManager
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * Activity that handles unlocking the vault specifically for Autofill requests.
 * Triggers biometric first, with a fallback to Master Password.
 */
@AndroidEntryPoint
class AutofillUnlockActivity : FragmentActivity() {

    @Inject lateinit var masterPasswordManager: MasterPasswordManager
    @Inject lateinit var vaultRepository: PasswordRepository

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
                    isManual = isManualSearch,
                    onUnlocked = { 
                        if (isManualSearch) {
                            // The screen will switch to manual search view via state
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
            val credentials = repository.getPasswords().filter {
                it.serviceName.contains(domain, ignoreCase = true) ||
                domain.contains(it.serviceName, ignoreCase = true)
            }

            val response = FillResponse.Builder()
            credentials.forEach { cred ->
                val label = if (isUnverified) "⚠️ UNVERIFIED: ${cred.username}" else cred.username
                val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                    setTextViewText(android.R.id.text1, label)
                }
                val datasetBuilder = Dataset.Builder(presentation)
                usernameId?.let { datasetBuilder.setValue(it, AutofillValue.forText(cred.username)) }
                passwordId?.let { datasetBuilder.setValue(it, AutofillValue.forText(cred.password)) }
                response.addDataset(datasetBuilder.build())
            }

            val resultIntent = Intent()
            resultIntent.putExtra(android.view.autofill.AutofillManager.EXTRA_AUTHENTICATION_RESULT, response.build())
            setResult(Activity.RESULT_OK, resultIntent)
            finish()
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
        resultIntent.putExtra(android.view.autofill.AutofillManager.EXTRA_AUTHENTICATION_RESULT, response.build())
        setResult(Activity.RESULT_OK, resultIntent)
        finish()
    }
}

@Composable
fun AutofillUnlockScreen(
    masterPasswordManager: MasterPasswordManager,
    vaultRepository: PasswordRepository,
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
                        try {
                            masterPasswordManager.unlockVault(context, password.toCharArray())
                            masterPasswordManager.authorizeAutofill()
                            isAuthenticated = true
                            onUnlocked()
                        } catch (e: Exception) {
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

    // Auto-trigger biometric on first launch
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
    val context = LocalContext.current
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
                masterPasswordManager.authorizeAutofill()
                onSuccess()
            }
        })

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("ZeroKey Autofill")
        .setSubtitle("Authenticate to access your vault")
        .setAllowedAuthenticators(androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG or 
                                 androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL)
        .build()

    biometricPrompt.authenticate(promptInfo)
}
