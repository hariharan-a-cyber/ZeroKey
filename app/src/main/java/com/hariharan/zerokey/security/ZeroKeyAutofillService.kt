package com.hariharan.zerokey.security

import android.app.assist.AssistStructure
import android.os.CancellationSignal
import android.service.autofill.*
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.hariharan.zerokey.data.database.PasswordDatabase
import com.hariharan.zerokey.data.model.PasswordItem
import com.hariharan.zerokey.data.repository.PasswordRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * ZeroKeyAutofillService
 *
 * Phishing-Resistant Autofill:
 * - Extracts domain from the requesting app/webpage
 * - Validates via DomainVerificationManager before ANY credential is returned
 */
class ZeroKeyAutofillService : AutofillService() {

    private val domainVerifier = DomainVerificationManager(DigitalAssetLinksVerifier())
    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.lastOrNull()?.structure ?: run {
            callback.onSuccess(null)
            return
        }

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
                    Log.w("ZeroKeyAutofill", "Autofill BLOCKED: ${verificationResult.reason}")
                    callback.onSuccess(null)
                    return@launch
                }

                val verifiedDomain = (verificationResult as DomainVerificationResult.Verified).verifiedDomain

                // ── CREDENTIAL LOOKUP ────────────────────────────────────────
                val database = PasswordDatabase.getDatabase(this@ZeroKeyAutofillService)
                val repository = PasswordRepository(database.passwordDao())
                
                val credentials = repository.getPasswords().filter { 
                    it.serviceName.contains(verifiedDomain, ignoreCase = true) || 
                    verifiedDomain.contains(it.serviceName, ignoreCase = true)
                }

                if (credentials.isEmpty()) {
                    callback.onSuccess(null)
                    return@launch
                }

                val response = FillResponse.Builder()

                credentials.forEach { cred: PasswordItem ->
                    val presentation = RemoteViews(packageName, android.R.layout.simple_list_item_1).apply {
                        setTextViewText(android.R.id.text1, cred.username)
                    }
                    
                    val datasetBuilder = Dataset.Builder(presentation)
                    parseResult.usernameId?.let {
                        datasetBuilder.setValue(it, AutofillValue.forText(cred.username))
                    }
                    parseResult.passwordId?.let {
                        datasetBuilder.setValue(it, AutofillValue.forText(cred.password))
                    }
                    response.addDataset(datasetBuilder.build())
                }

                callback.onSuccess(response.build())

            } catch (e: Exception) {
                Log.e("ZeroKeyAutofill", "Fill request failed", e)
                callback.onFailure("Autofill error: ${e.message}")
            }
        }
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        callback.onSuccess()
    }

    private fun parseStructure(structure: AssistStructure): ParsedStructure {
        var usernameId: AutofillId? = null
        var passwordId: AutofillId? = null
        var domain: String? = null
        var packageName: String? = null
        var webDomain: String? = null

        fun traverse(node: AssistStructure.ViewNode) {
            packageName = node.idPackage
            node.webDomain?.let {
                webDomain = it
                domain = extractRegistrableDomain(it)
            }

            val hints = node.autofillHints
            if (hints != null) {
                if (hints.contains(android.view.View.AUTOFILL_HINT_USERNAME) ||
                    hints.contains(android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS)) {
                    usernameId = node.autofillId
                } else if (hints.contains(android.view.View.AUTOFILL_HINT_PASSWORD)) {
                    passwordId = node.autofillId
                }
            }

            for (i in 0 until node.childCount) traverse(node.getChildAt(i))
        }

        for (i in 0 until structure.windowNodeCount) {
            traverse(structure.getWindowNodeAt(i).rootViewNode)
        }

        return ParsedStructure(usernameId, passwordId, domain, packageName, webDomain)
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
}
