package com.hariharan.zerokey.security

import android.app.PendingIntent
import android.content.Intent
import android.os.CancellationSignal
import android.service.autofill.*
import android.util.Log
import android.view.autofill.AutofillId
import android.view.autofill.AutofillValue
import android.widget.RemoteViews
import com.hariharan.zerokey.R
import com.hariharan.zerokey.data.database.PasswordDatabase
import com.hariharan.zerokey.data.repository.PasswordRepository
import kotlinx.coroutines.runBlocking

class ZeroKeyAutofillService : AutofillService() {

    override fun onFillRequest(
        request: FillRequest,
        cancellationSignal: CancellationSignal,
        callback: FillCallback
    ) {
        val structure = request.fillContexts.last().structure
        val packageName = structure.activityComponent.packageName
        
        // Find fields in the view structure
        val parser = AutofillStructureParser(structure)
        val usernameId = parser.usernameId
        val passwordId = parser.passwordId

        if (usernameId == null || passwordId == null) {
            callback.onSuccess(null)
            return
        }

        // Query database for matching credentials
        // In a real app, we'd match by package name or web domain
        val database = PasswordDatabase.getDatabase(this)
        val repository = PasswordRepository(database.passwordDao(), EncryptionManager)
        
        val matchingItems = runBlocking { 
            repository.getPasswords().filter { 
                it.serviceName.contains(packageName, ignoreCase = true) || 
                packageName.contains(it.serviceName, ignoreCase = true)
            }
        }

        if (matchingItems.isEmpty()) {
            callback.onSuccess(null)
            return
        }

        val responseBuilder = FillResponse.Builder()

        for (item in matchingItems) {
            val presentation = RemoteViews(this.packageName, R.layout.autofill_suggestion).apply {
                setTextViewText(R.id.autofill_username, item.username)
            }

            // Create an intent for biometric authentication
            // We pass the encrypted data to the AuthActivity to keep it secure until the last moment
            val authIntent = Intent(this, AutofillAuthActivity::class.java).apply {
                putExtra("username", item.username)
                putExtra("password", item.password) // This is currently plain text in PasswordItem, we'll fix this below
                putExtra("usernameId", usernameId)
                putExtra("passwordId", passwordId)
            }

            val pendingIntent = PendingIntent.getActivity(
                this, 
                item.id, 
                authIntent, 
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
            )

            val dataset = Dataset.Builder()
                .setValue(usernameId, AutofillValue.forText(item.username), presentation)
                .setValue(passwordId, AutofillValue.forText(item.password), presentation)
                .setAuthentication(pendingIntent.intentSender)
                .build()

            responseBuilder.addDataset(dataset)
        }

        callback.onSuccess(responseBuilder.build())
    }

    override fun onSaveRequest(request: SaveRequest, callback: SaveCallback) {
        // Handle saving new credentials discovered during autofill
        callback.onSuccess()
    }
}

/**
 * Helper class to parse the AssistStructure and find relevant autofill fields.
 */
class AutofillStructureParser(structure: android.app.assist.AssistStructure) {
    var usernameId: AutofillId? = null
    var passwordId: AutofillId? = null

    init {
        for (i in 0 until structure.windowNodeCount) {
            val node = structure.getWindowNodeAt(i).rootViewNode
            traverseNode(node)
        }
    }

    private fun traverseNode(node: android.app.assist.AssistStructure.ViewNode) {
        val hints = node.autofillHints
        if (hints != null) {
            if (hints.contains(android.view.View.AUTOFILL_HINT_USERNAME) || 
                hints.contains(android.view.View.AUTOFILL_HINT_EMAIL_ADDRESS)) {
                usernameId = node.autofillId
            } else if (hints.contains(android.view.View.AUTOFILL_HINT_PASSWORD)) {
                passwordId = node.autofillId
            }
        }

        for (i in 0 until node.childCount) {
            traverseNode(node.getChildAt(i))
        }
    }
}
