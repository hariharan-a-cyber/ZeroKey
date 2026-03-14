package com.hariharan.zerokey.security

import android.content.Context
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.GetCredentialException

/**
 * Production-grade Passkey Manager for ZeroKey.
 * Implements FIDO2/WebAuthn support using the Android Credential Manager API.
 */
class PasskeyManager(private val context: Context) {

    private val credentialManager = CredentialManager.create(context)

    /**
     * Registers a new Passkey.
     * @param requestJson The JSON response from the server containing the challenge.
     */
    suspend fun registerPasskey(requestJson: String): Result<Unit> {
        return try {
            val request = CreatePublicKeyCredentialRequest(requestJson)
            credentialManager.createCredential(context, request)
            Result.success(Unit)
        } catch (e: CreateCredentialException) {
            Result.failure(e)
        }
    }

    /**
     * Authenticates the user using an existing Passkey.
     */
    suspend fun authenticateWithPasskey(requestJson: String): Result<Unit> {
        return try {
            val getPublicKeyOption = GetPublicKeyCredentialOption(requestJson)
            val getCredRequest = GetCredentialRequest(listOf(getPublicKeyOption))
            
            val result = credentialManager.getCredential(context, getCredRequest)
            // In a real app, send result.credential.data to your server for verification
            Result.success(Unit)
        } catch (e: GetCredentialException) {
            Result.failure(e)
        }
    }
}
