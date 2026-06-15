package com.hariharan.zerokey.security

import android.app.PendingIntent
import android.app.assist.AssistStructure
import android.content.Intent
import android.os.Build
import android.os.CancellationSignal
import android.service.autofill.*
import android.view.View
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.view.inputmethod.EditorInfo
import android.widget.RemoteViews
import androidx.autofill.inline.v1.InlineSuggestionUi
import com.hariharan.zerokey.R
import com.hariharan.zerokey.core.database.PasswordDatabase
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import com.hariharan.zerokey.core.common.PrivacyLogger
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

import com.hariharan.zerokey.core.security.MasterPasswordManager
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * ZeroKeyAutofillService
 *
 * Phishing-Resistant Autofill:
 * - Extracts domain from the requesting app/webpage
 * - Validates via DomainVerificationManager before ANY credential is returned
 */
@AndroidEntryPoint
class ZeroKeyAutofillService : AutofillService() {

    @Inject lateinit var masterPasswordManager: MasterPasswordManager
    @Inject lateinit var vaultRepository: PasswordRepository

    private val domainVerifier = DomainVerificationManager(DigitalAssetLinksVerifier())
    private val scope = CoroutineScope(Dispatchers.IO)

    // Abuse Protection: Throttling state
    companion object {
        private val requestHistory = mutableMapOf<String, MutableList<Long>>()
        private const val MAX_REQUESTS_PER_WINDOW = 5
        private const val WINDOW_MS = 10_000L // 10 seconds
    }

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess(null)
            return
        }

        val callingPackage = request.fillContexts.lastOrNull()?.structure?.activityComponent?.packageName ?: "unknown"
        if (isThrottled(callingPackage)) {
            PrivacyLogger.w("ZeroKeyAutofill", "Request THROTTLED for ${PrivacyLogger.mask(callingPackage)}")
            callback.onSuccess(null)
            return
        }

        // --- TIERED SECURITY RESPONSE ---
        val securityStatus = SecurityHardening.checkDeviceSecurity(this)
        val countermeasure = SecurityHardening.getRecommendedCountermeasure(securityStatus)
        
        if (countermeasure == SecurityHardening.Countermeasure.DISABLE_AUTOFILL) {
            PrivacyLogger.w("ZeroKeyAutofill", "Autofill DISABLED due to active threat (Frida/Tamper)")
            callback.onSuccess(null)
            return
        }
        
        val isTrustDegraded = countermeasure == SecurityHardening.Countermeasure.DEGRADE_TRUST

        scope.launch {
            try {
                val parseResult = parseStructure(structure)
                if (parseResult.usernameId == null && parseResult.passwordId == null) {
                    callback.onSuccess(null)
                    return@launch
                }

                // ── DOMAIN VALIDATION ────────────────────────────────────────
                val verificationResult = domainVerifier.verify(
                    requestedDomain = parseResult.domain,
                    packageName = parseResult.packageName,
                    webDomain = parseResult.webDomain
                )

                if (verificationResult is DomainVerificationResult.Blocked) {
                    PrivacyLogger.w("ZeroKeyAutofill", "Autofill BLOCKED: ${PrivacyLogger.sanitizeError(verificationResult.reason)}")
                    callback.onSuccess(null)
                    return@launch
                }

                val verifiedDomain = when (verificationResult) {
                    is DomainVerificationResult.Verified -> verificationResult.verifiedDomain
                    is DomainVerificationResult.Unverified -> verificationResult.domain
                    else -> ""
                }
                val isUnverified = verificationResult is DomainVerificationResult.Unverified

                // ── CHECK IF FILL IS AUTHORIZED ───────────────────────────
                // Even if the vault is "unlocked", we require fresh auth based on user policy
                if (!masterPasswordManager.isAutofillAuthorized(this@ZeroKeyAutofillService)) {
                    val intent = Intent(this@ZeroKeyAutofillService, AutofillUnlockActivity::class.java).apply {
                        putExtra("username_id", parseResult.usernameId)
                        putExtra("password_id", parseResult.passwordId)
                        putExtra("verified_domain", verifiedDomain)
                        putExtra("is_unverified", isUnverified)
                        putExtra("manual_search", false)
                    }
                    
                    val pendingIntent = PendingIntent.getActivity(
                        this@ZeroKeyAutofillService, 
                        0, 
                        intent, 
                        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                    )

                    val presentation = RemoteViews(packageName, R.layout.autofill_suggestion).apply {
                        setTextViewText(R.id.autofill_username, "Tap to Unlock ZeroKey")
                    }

                    val responseBuilder = FillResponse.Builder()

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                        request.inlineSuggestionsRequest?.let { inlineRequest ->
                            val specs = inlineRequest.inlinePresentationSpecs
                            if (specs.isNotEmpty()) {
                                val inlinePresentation = InlinePresentation(
                                    InlineSuggestionUi.newContentBuilder(pendingIntent)
                                        .setTitle("Unlock ZeroKey")
                                        .build()
                                        .slice,
                                    specs[0],
                                    false
                                )
                                responseBuilder.setAuthentication(
                                    arrayOf(parseResult.usernameId, parseResult.passwordId).filterNotNull().toTypedArray(),
                                    pendingIntent.intentSender,
                                    presentation,
                                    inlinePresentation
                                )
                            } else {
                                responseBuilder.setAuthentication(
                                    arrayOf(parseResult.usernameId, parseResult.passwordId).filterNotNull().toTypedArray(),
                                    pendingIntent.intentSender,
                                    presentation
                                )
                            }
                        } ?: run {
                            responseBuilder.setAuthentication(
                                arrayOf(parseResult.usernameId, parseResult.passwordId).filterNotNull().toTypedArray(),
                                pendingIntent.intentSender,
                                presentation
                            )
                        }
                    } else {
                        responseBuilder.setAuthentication(
                            arrayOf(parseResult.usernameId, parseResult.passwordId).filterNotNull().toTypedArray(),
                            pendingIntent.intentSender,
                            presentation
                        )
                    }

                    callback.onSuccess(responseBuilder.build())
                    return@launch
                }

                // ── CREDENTIAL LOOKUP ────────────────────────────────────────
                val repository = vaultRepository

                val response = FillResponse.Builder()
                val inlineRequest = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                    request.inlineSuggestionsRequest
                } else null

                val normalizedVerifiedDomain = extractRegistrableDomain(verifiedDomain)
                
                // If trust is degraded (debugger attached), we skip automatic matching
                // and only provide the manual search fallback.
                val credentials = if (isTrustDegraded) {
                    PrivacyLogger.w("ZeroKeyAutofill", "Trust Degraded: Skipping automatic matching")
                    emptyList()
                } else {
                    repository.getPasswords().filter { cred: PasswordItem ->
                        val normalizedService = extractRegistrableDomain(cred.serviceName)
                        cred.serviceName.contains(verifiedDomain, ignoreCase = true) || 
                        verifiedDomain.contains(cred.serviceName, ignoreCase = true) ||
                        (normalizedService.isNotEmpty() && normalizedVerifiedDomain.isNotEmpty() && 
                         normalizedService == normalizedVerifiedDomain)
                    }.sortedByDescending { it.serviceName.equals(verifiedDomain, ignoreCase = true) } // Basic ranking
                }

                // ── ADD MANUAL SEARCH OPTION ─────────────────────────────────
                val manualIntent = Intent(this@ZeroKeyAutofillService, AutofillUnlockActivity::class.java).apply {
                    putExtra("username_id", parseResult.usernameId)
                    putExtra("password_id", parseResult.passwordId)
                    putExtra("manual_search", true)
                }
                val manualPendingIntent = PendingIntent.getActivity(
                    this@ZeroKeyAutofillService,
                    1,
                    manualIntent,
                    PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
                )
                val manualPresentation = RemoteViews(packageName, R.layout.autofill_suggestion).apply {
                    setTextViewText(R.id.autofill_username, "🔍 Search ZeroKey...")
                }
                
                val manualDatasetBuilder = Dataset.Builder(manualPresentation)
                    .setAuthentication(manualPendingIntent.intentSender)
                
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inlineRequest != null) {
                    val spec = inlineRequest.inlinePresentationSpecs.firstOrNull()
                    if (spec != null) {
                        val inlineManual = InlinePresentation(
                            InlineSuggestionUi.newContentBuilder(manualPendingIntent)
                                .setTitle("Search ZeroKey")
                                .build()
                                .slice,
                            spec,
                            false
                        )
                        manualDatasetBuilder.setInlinePresentation(inlineManual)
                    }
                }
                
                // Add fields to manual dataset so it knows where to fill
                parseResult.usernameId?.let { manualDatasetBuilder.setValue(it, null) }
                parseResult.passwordId?.let { manualDatasetBuilder.setValue(it, null) }
                
                response.addDataset(manualDatasetBuilder.build())

                if (credentials.isNotEmpty()) {
                    credentials.forEachIndexed { index, cred: PasswordItem ->
                        val label = if (isUnverified) "⚠️ UNVERIFIED: ${cred.username}" else cred.username
                        
                        // Dropdown Presentation
                        val presentation = RemoteViews(packageName, R.layout.autofill_suggestion).apply {
                            setTextViewText(R.id.autofill_username, label)
                        }
                        
                        val datasetBuilder = Dataset.Builder(presentation)

                        // Inline Presentation (Android 11+)
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R && inlineRequest != null) {
                            val spec = if (index < inlineRequest.inlinePresentationSpecs.size) {
                                inlineRequest.inlinePresentationSpecs[index]
                            } else {
                                inlineRequest.inlinePresentationSpecs.last()
                            }

                            val inlinePresentation = InlinePresentation(
                                InlineSuggestionUi.newContentBuilder(PendingIntent.getActivity(this@ZeroKeyAutofillService, 0, Intent(), PendingIntent.FLAG_IMMUTABLE))
                                    .setTitle(label)
                                    .build()
                                    .slice,
                                spec,
                                false
                            )
                            datasetBuilder.setInlinePresentation(inlinePresentation)
                        }

                        parseResult.usernameId?.let {
                            datasetBuilder.setValue(it, AutofillValue.forText(cred.username))
                        }
                        parseResult.passwordId?.let {
                            val passwordBytes = cred.getPasswordAsBytes()
                            try {
                                val passwordStr = passwordBytes.decodeToString()
                                datasetBuilder.setValue(it, AutofillValue.forText(passwordStr))
                            } finally {
                                passwordBytes.fill(0)
                            }
                        }
                        response.addDataset(datasetBuilder.build())
                    }
                }

                callback.onSuccess(response.build())

            } catch (e: Exception) {
                PrivacyLogger.e("ZeroKeyAutofill", "Fill request failed: ${PrivacyLogger.sanitizeError(e.message)}")
                callback.onFailure("Autofill error: ${e.message}")
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: return callback.onSuccess()
        
        scope.launch {
            try {
                val parsed = parseStructureWithValues(structure)
                if (parsed.username != null && parsed.password != null) {
                    val domain = parsed.webDomain ?: parsed.packageName ?: "Unknown"
                    val repository = vaultRepository
                    
                    val existing = repository.getPasswords().find { 
                        it.serviceName.contains(domain, ignoreCase = true) && it.username == parsed.username 
                    }
                    
                    if (existing != null) {
                        if (existing.password != parsed.password) {
                            PrivacyLogger.i("ZeroKeyAutofill", "Updating password for masked_domain: ${PrivacyLogger.mask(domain)}")
                            repository.savePassword(existing.serviceName, parsed.username, parsed.password, existing.notes, id = existing.id)
                        }
                    } else {
                        PrivacyLogger.i("ZeroKeyAutofill", "Saving new password for masked_domain: ${PrivacyLogger.mask(domain)}")
                        repository.savePassword(domain, parsed.username, parsed.password, null)
                    }
                }
                callback.onSuccess()
            } catch (e: Exception) {
                PrivacyLogger.e("ZeroKeyAutofill", "Save failed: ${PrivacyLogger.sanitizeError(e.message)}")
                callback.onFailure("Save error: ${e.message}")
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        masterPasswordManager.onTrimMemory(level)
    }

    private fun parseStructureWithValues(structure: AssistStructure): ParsedStructureWithValues {
        var username: String? = null
        var password: String? = null
        var packageName: String? = null
        var webDomain: String? = null

        fun traverse(node: AssistStructure.ViewNode) {
            val identity = "${node.idEntry} ${node.hint}".lowercase()
            val text = node.autofillValue?.textValue?.toString() ?: node.text?.toString()

            if (node.webDomain != null) webDomain = node.webDomain
            if (node.idPackage != null) packageName = node.idPackage

            if (node.inputType and EditorInfo.TYPE_TEXT_VARIATION_PASSWORD != 0 || 
                identity.contains("password")) {
                if (text != null && text.isNotBlank()) password = text
            } else if (identity.contains("username") || identity.contains("login") || identity.contains("email")) {
                if (text != null && text.isNotBlank()) username = text
            }

            for (i in 0 until node.childCount) traverse(node.getChildAt(i))
        }

        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
        }
        return ParsedStructureWithValues(username, password, packageName, webDomain)
    }

    private fun parseStructure(structure: AssistStructure): ParsedStructure {
        var bestUsernameId: AutofillId? = null
        var bestPasswordId: AutofillId? = null
        var maxUsernameScore = -1
        var maxPasswordScore = -1
        
        var domain: String? = null
        var packageName: String? = null
        var webDomain: String? = null

        fun traverse(node: AssistStructure.ViewNode) {
            val nodeId = node.idEntry ?: ""
            val nodeHint = node.hint ?: ""
            val nodeContentDescription = node.contentDescription ?: ""
            
            // Masked package for production safety
            PrivacyLogger.d("ZeroKeyAutofill", "Node Scan: class=${node.className}, pkg=${PrivacyLogger.mask(node.idPackage)}")

            packageName = node.idPackage
            node.webDomain?.let {
                webDomain = it
                domain = extractRegistrableDomain(it)
            }

            // --- Confidence Scoring ---
            var userScore = 0
            var passScore = 0

            val hints = node.autofillHints
            if (hints != null) {
                if (hints.contains(View.AUTOFILL_HINT_USERNAME) || hints.contains(View.AUTOFILL_HINT_EMAIL_ADDRESS)) userScore += 100
                if (hints.contains(View.AUTOFILL_HINT_PASSWORD)) passScore += 100
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && node.htmlInfo != null) {
                val tag = node.htmlInfo?.tag ?: ""
                val attrs = node.htmlInfo?.attributes ?: emptyList()
                if (tag.equals("input", ignoreCase = true)) {
                    for (attr in attrs) {
                        val name = attr.first.lowercase()
                        val value = attr.second.lowercase()
                        if (name == "type" && value == "password") passScore += 90
                        if ((name == "name" || name == "id") && (value.contains("user") || value.contains("email") || value.contains("login"))) userScore += 70
                    }
                }
            }

            if (node.inputType and EditorInfo.TYPE_TEXT_VARIATION_PASSWORD != 0 ||
                node.inputType and EditorInfo.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD != 0 ||
                node.inputType and EditorInfo.TYPE_TEXT_VARIATION_WEB_PASSWORD != 0) {
                passScore += 80
            }
            
            val identity = "$nodeId $nodeHint $nodeContentDescription".lowercase()
            if (identity.contains("password") || identity.contains("passwd") || identity.contains("pwd")) passScore += 50
            if (identity.contains("username") || identity.contains("login") || identity.contains("email")) userScore += 40

            // Exclude search fields
            if (identity.contains("search") || identity.contains("find")) {
                userScore -= 60
                passScore -= 60
            }

            if (userScore > maxUsernameScore && userScore > 30) {
                maxUsernameScore = userScore
                bestUsernameId = node.autofillId
            }
            if (passScore > maxPasswordScore && passScore > 30) {
                maxPasswordScore = passScore
                bestPasswordId = node.autofillId
            }

            for (i in 0 until node.childCount) traverse(node.getChildAt(i))
        }

        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
        }

        return ParsedStructure(bestUsernameId, bestPasswordId, domain, packageName, webDomain)
    }

    private fun extractRegistrableDomain(host: String): String {
        val parts = host.lowercase().split(".")
        return if (parts.size >= 2) "${parts[parts.size - 2]}.${parts[parts.size - 1]}"
        else host
    }

    data class ParsedStructure(
        val usernameId: AutofillId?,
        val passwordId: AutofillId?,
        val domain: String?,
        val packageName: String?,
        val webDomain: String?
    )

    data class ParsedStructureWithValues(
        val username: String?,
        val password: String?,
        val packageName: String?,
        val webDomain: String?
    )

    @Synchronized
    private fun isThrottled(packageName: String): Boolean {
        val now = System.currentTimeMillis()
        val history = requestHistory.getOrPut(packageName) { mutableListOf() }
        history.removeIf { it < now - WINDOW_MS }

        if (history.size >= MAX_REQUESTS_PER_WINDOW) return true

        history.add(now)
        return false
    }
}
