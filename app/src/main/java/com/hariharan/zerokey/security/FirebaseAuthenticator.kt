package com.hariharan.zerokey.security

import android.content.Context
import com.hariharan.zerokey.core.common.PrivacyLogger
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import kotlinx.coroutines.tasks.await

/**
 * FINAL RE-WRITTEN MODERNIZED IMPLEMENTATION (2026 Recommended Stack)
 * This version explicitly uses .setFilterByAuthorizedAccounts(false) to ensure all accounts appear.
 */
class FirebaseAuthenticator {

    private val auth: FirebaseAuth = FirebaseAuth.getInstance()

    val currentUser: FirebaseUser?
        get() = auth.currentUser

    val isAuthenticated: Boolean
        get() = auth.currentUser != null

    val uid: String?
        get() = auth.currentUser?.uid

    /**
     * Sign up with Email/Password.
     */
    suspend fun signUp(email: String, password: String): AuthResult {
        return try {
            val result = auth.createUserWithEmailAndPassword(email, password).await()
            val user = result.user ?: return AuthResult.Error("Sign-up failed")
            AuthResult.Success(user)
        } catch (e: com.google.firebase.auth.FirebaseAuthUserCollisionException) {
            AuthResult.Error("An account already exists for this email")
        } catch (e: com.google.firebase.auth.FirebaseAuthWeakPasswordException) {
            AuthResult.Error("Password is too weak (use 8+ characters)")
        } catch (e: Exception) {
            PrivacyLogger.e("FirebaseAuthenticator", "SignUp failed: ${e.message}")
            AuthResult.Error("Sign-up failed. Check your connection and try again.")
        }
    }

    /**
     * Sign in with Email/Password.
     */
    suspend fun signIn(email: String, password: String): AuthResult {
        return try {
            val result = auth.signInWithEmailAndPassword(email, password).await()
            val user = result.user ?: return AuthResult.Error("Sign-in failed")
            AuthResult.Success(user)
        } catch (e: com.google.firebase.auth.FirebaseAuthInvalidCredentialsException) {
            AuthResult.Error("Incorrect email or password")
        } catch (e: com.google.firebase.auth.FirebaseAuthInvalidUserException) {
            AuthResult.Error("No account found for this email")
        } catch (e: Exception) {
            PrivacyLogger.e("FirebaseAuthenticator", "SignIn failed: ${e.message}")
            AuthResult.Error("Sign-in failed. Check your connection and try again.")
        }
    }

    /**
     * Sign in with Google using Android Credential Manager.
     */
    suspend fun signInWithGoogle(context: Context, serverClientId: String): FirebaseUser? {
        val credentialManager = CredentialManager.create(context)
        val nonce = java.util.UUID.randomUUID().toString()

        PrivacyLogger.d("FirebaseAuthenticator", "FORCED RE-INIT: Sign-In with Client ID: $serverClientId")

        // FORCED CONFIGURATION: setFilterByAuthorizedAccounts(false)
        val googleIdOption = GetGoogleIdOption.Builder()
            .setFilterByAuthorizedAccounts(false) 
            .setServerClientId(serverClientId)
            .setNonce(nonce)
            .setAutoSelectEnabled(false)
            .build()

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(googleIdOption)
            .build()

        return try {
            val result = credentialManager.getCredential(context, request)
            handleGoogleCredential(result)
        } catch (e: NoCredentialException) {
            PrivacyLogger.e("FirebaseAuthenticator", "CRITICAL ERROR: No credentials found. Check Test User list in Google Cloud Console.")
            null
        } catch (e: GetCredentialException) {
            PrivacyLogger.e("FirebaseAuthenticator", "Credential Manager Error: ${e.type} - ${e.message}")
            null
        } catch (e: Exception) {
            PrivacyLogger.e("FirebaseAuthenticator", "Unexpected Error: ${e.message}", e)
            null
        }
    }

    private suspend fun handleGoogleCredential(result: GetCredentialResponse): FirebaseUser? {
        val credential = result.credential
        PrivacyLogger.d("FirebaseAuthenticator", "Processing credential type: ${credential.type}")
        
        return when {
            credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL -> {
                try {
                    val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                    val firebaseCredential = GoogleAuthProvider.getCredential(googleIdTokenCredential.idToken, null)
                    val authResult = auth.signInWithCredential(firebaseCredential).await()
                    authResult.user
                } catch (e: GoogleIdTokenParsingException) {
                    PrivacyLogger.e("FirebaseAuthenticator", "Invalid Google ID Token", e)
                    null
                } catch (e: Exception) {
                    PrivacyLogger.e("FirebaseAuthenticator", "Firebase Sign-In failed: ${e.message}")
                    null
                }
            }
            else -> {
                PrivacyLogger.e("FirebaseAuthenticator", "Unexpected credential type: ${credential.type}")
                null
            }
        }
    }

    suspend fun signOut(context: Context) {
        auth.signOut()
        val credentialManager = CredentialManager.create(context)
        try {
            credentialManager.clearCredentialState(ClearCredentialStateRequest())
        } catch (e: Exception) {
            PrivacyLogger.e("FirebaseAuthenticator", "Clear credential state failed", e)
        }
    }
}

sealed class AuthResult {
    data class Success(val user: com.google.firebase.auth.FirebaseUser) : AuthResult()
    data class Error(val message: String) : AuthResult()
}
