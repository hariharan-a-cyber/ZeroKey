package com.hariharan.zerokey

import android.content.Context
import androidx.credentials.CredentialManager
import androidx.credentials.CustomCredential
import androidx.credentials.GetCredentialRequest
import com.google.android.libraries.identity.googleid.GetGoogleIdOption
import com.google.android.libraries.identity.googleid.GoogleIdTokenCredential
import com.google.android.libraries.identity.googleid.GoogleIdTokenParsingException
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.auth.GoogleAuthProvider
import kotlinx.coroutines.tasks.await

class GoogleAuthManager {

    private val auth = FirebaseAuth.getInstance()

    suspend fun signIn(
        context: Context,
        webClientId: String
    ): Boolean {

        return try {

            val googleIdOption = GetGoogleIdOption.Builder()
                .setFilterByAuthorizedAccounts(false)
                .setServerClientId(webClientId)
                .setAutoSelectEnabled(false)
                .build()

            val request = GetCredentialRequest.Builder()
                .addCredentialOption(googleIdOption)
                .build()

            val credentialManager = CredentialManager.create(context)

            val result = credentialManager.getCredential(
                context = context,
                request = request
            )

            val credential = result.credential

            if (
                credential is CustomCredential &&
                credential.type == GoogleIdTokenCredential.TYPE_GOOGLE_ID_TOKEN_CREDENTIAL
            ) {

                val googleCredential = GoogleIdTokenCredential
                    .createFrom(credential.data)

                val firebaseCredential = GoogleAuthProvider.getCredential(
                    googleCredential.idToken,
                    null
                )

                auth.signInWithCredential(firebaseCredential).await()

                true

            } else {
                false
            }

        } catch (e: GoogleIdTokenParsingException) {
            e.printStackTrace()
            false

        } catch (e: Exception) {
            e.printStackTrace()
            false
        }
    }
}
