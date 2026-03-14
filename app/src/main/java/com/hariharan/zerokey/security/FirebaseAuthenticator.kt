package com.hariharan.zerokey.security

import android.content.Context
import android.util.Log
import androidx.credentials.ClearCredentialStateRequest
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import com.google.android.libraries.identity.googleid.GetSignInWithGoogleOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.FirebaseUser
import com.google.firebase.auth.GoogleAuthProvider
import kotlinx.coroutines.tasks.await

/**
 * Handles Firebase Authentication for user identity.
 * Supports Email/Password and Google Sign-In via Credentials Manager.
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
    suspend fun signUp(email: String, password: String): FirebaseUser? {
        return try {
            val result = auth.createUserWithEmailAndPassword(email, password).await()
            result.user
        } catch (e: Exception) {
            Log.e("FirebaseAuthenticator", "SignUp failed: ${e.message}")
            null
        }
    }

    /**
     * Sign in with Email/Password.
     */
    suspend fun signIn(email: String, password: String): FirebaseUser? {
        return try {
            val result = auth.signInWithEmailAndPassword(email, password).await()
            result.user
        } catch (e: Exception) {
            Log.e("FirebaseAuthenticator", "SignIn failed: ${e.message}")
            null
        }
    }

    /**
     * Sign in with Google using Credentials Manager.
     */
    suspend fun signInWithGoogle(context: Context, serverClientId: String): FirebaseUser? {
        val credentialManager = CredentialManager.create(context)

        // Using GetSignInWithGoogleOption for explicit button clicks as recommended by documentation
        val signInWithGoogleOption = GetSignInWithGoogleOption.Builder(serverClientId)
            .build()

        val request = GetCredentialRequest.Builder()
            .addCredentialOption(signInWithGoogleOption)
            .build()

        return try {
            val result = credentialManager.getCredential(context, request)
            handleGoogleCredential(result)
        } catch (e: NoCredentialException) {
            Log.e("FirebaseAuthenticator", "No Google accounts found. Ensure a Google account is signed in on the device and SHA-1 is correctly configured in Firebase Console.")
            null
        } catch (e: GetCredentialException) {
            Log.e("FirebaseAuthenticator", "Credential Manager Error: ${e.type} - ${e.message}")
            null
        } catch (e: Exception) {
            Log.e("FirebaseAuthenticator", "Unexpected Google Sign-In Error", e)
            null
        }
    }

    private suspend fun handleGoogleCredential(result: GetCredentialResponse): FirebaseUser? {
        val credential = result.credential
        
        return when {
            credential is CustomCredential && credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL -> {
                try {
                    val googleIdTokenCredential = GoogleIdTokenCredential.createFrom(credential.data)
                    val firebaseCredential = GoogleAuthProvider.getCredential(googleIdTokenCredential.idToken, null)
                    val authResult = auth.signInWithCredential(firebaseCredential).await()
                    authResult.user
                } catch (e: GoogleIdTokenParsingException) {
                    Log.e("FirebaseAuthenticator", "Received an invalid google id token response", e)
                    null
                }
            }
            else -> {
                Log.e("FirebaseAuthenticator", "Received unexpected credential type: ${credential.type}")
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
            Log.e("FirebaseAuthenticator", "Clear credential state failed", e)
        }
    }
}
