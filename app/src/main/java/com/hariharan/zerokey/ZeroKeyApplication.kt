package com.hariharan.zerokey

import android.app.Application
import com.google.firebase.appcheck.ktx.appCheck
import com.google.firebase.appcheck.playintegrity.PlayIntegrityAppCheckProviderFactory
import com.google.firebase.appcheck.debug.DebugAppCheckProviderFactory
import com.google.firebase.ktx.Firebase
import dagger.hilt.android.HiltAndroidApp

@HiltAndroidApp
class ZeroKeyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        com.hariharan.zerokey.core.common.PrivacyLogger.verboseEnabled =
            com.hariharan.zerokey.BuildConfig.DEBUG

        Firebase.appCheck.installAppCheckProviderFactory(
            if (com.hariharan.zerokey.BuildConfig.DEBUG)
                DebugAppCheckProviderFactory.getInstance()
            else
                PlayIntegrityAppCheckProviderFactory.getInstance()
        )
    }
}
