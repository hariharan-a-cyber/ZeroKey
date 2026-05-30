package com.hariharan.zerokey.security

import android.accessibilityservice.AccessibilityServiceInfo
import android.content.Context
import android.os.Build
import android.os.Debug
import com.hariharan.zerokey.core.common.PrivacyLogger
import android.view.accessibility.AccessibilityManager
import java.io.File
import java.io.BufferedReader
import java.io.FileReader

/**
 * SecurityHardening
 *
 * Implements a tiered response model to device security threats.
 */
object SecurityHardening {

    private const val TAG = "SecurityHardening"

    enum class RiskLevel { LOW, MEDIUM, HIGH }
    
    enum class Countermeasure { NONE, WARN, DEGRADE_TRUST, DISABLE_AUTOFILL, FORCE_LOCK }

    fun checkDeviceSecurity(context: Context): SecurityStatus {
        val isRooted = isRooted()
        val isDebuggerAttached = Debug.isDebuggerConnected()
        val isFridaDetected = isFridaDetected()
        val isEmulator = isEmulator()
        val accessibilityRisk = getAccessibilityRiskLevel(context)

        PrivacyLogger.i(TAG, "Security Scan: Rooted=$isRooted, Debugger=$isDebuggerAttached, Frida=$isFridaDetected, Emulator=$isEmulator, AccessibilityRisk=$accessibilityRisk")

        return SecurityStatus(
            isCompromised = isRooted || isDebuggerAttached || isFridaDetected,
            isRooted = isRooted,
            isDebuggerAttached = isDebuggerAttached,
            isFridaDetected = isFridaDetected,
            isEmulator = isEmulator,
            accessibilityRisk = accessibilityRisk,
            highRiskServices = getHighRiskServiceNames(context)
        )
    }

    fun getRecommendedCountermeasure(status: SecurityStatus): Countermeasure {
        return when {
            status.isFridaDetected -> Countermeasure.DISABLE_AUTOFILL
            status.isDebuggerAttached -> Countermeasure.DEGRADE_TRUST
            status.isRooted -> Countermeasure.WARN
            else -> Countermeasure.NONE
        }
    }

    private fun isRooted(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su"
        )
        for (path in paths) {
            if (File(path).exists()) return true
        }
        
        // Check Build Tags
        val buildTags = Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) return true

        return false
    }

    private fun isFridaDetected(): Boolean {
        // Basic check for Frida hooks in /proc/self/maps
        return try {
            val reader = BufferedReader(FileReader("/proc/self/maps"))
            var line: String?
            var detected = false
            while (reader.readLine().also { line = it } != null) {
                if (line!!.contains("frida", ignoreCase = true) || line!!.contains("gum-js", ignoreCase = true)) {
                    detected = true
                    break
                }
            }
            reader.close()
            detected
        } catch (e: Exception) {
            false
        }
    }

    private fun isEmulator(): Boolean {
        return (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic"))
                || Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.HARDWARE.contains("goldfish")
                || Build.HARDWARE.contains("ranchu")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.PRODUCT.contains("sdk_google")
                || Build.PRODUCT.contains("google_sdk")
                || Build.PRODUCT.contains("sdk")
                || Build.PRODUCT.contains("sdk_x86")
                || Build.PRODUCT.contains("vbox86p")
                || Build.PRODUCT.contains("emulator")
                || Build.PRODUCT.contains("simulator")
    }

    fun getAccessibilityRiskLevel(context: Context): RiskLevel {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        
        val highRiskServices = enabledServices.filter { service ->
            val packageName = service.resolveInfo.serviceInfo.packageName
            val isKnownSafe = packageName.startsWith("com.google.android.marvin.talkback") || 
                             packageName.startsWith("com.android.talkback")
            
            !isKnownSafe && (service.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0
        }

        return when {
            highRiskServices.isNotEmpty() -> RiskLevel.HIGH
            enabledServices.any { !it.resolveInfo.serviceInfo.packageName.startsWith("com.google.") } -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }

    fun getHighRiskServiceNames(context: Context): List<String> {
        val am = context.getSystemService(Context.ACCESSIBILITY_SERVICE) as AccessibilityManager
        val enabledServices = am.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
        
        return enabledServices.filter { service ->
            val packageName = service.resolveInfo.serviceInfo.packageName
            val isKnownSafe = packageName.startsWith("com.google.android.marvin.talkback") || 
                             packageName.startsWith("com.android.talkback")
            
            !isKnownSafe && (service.capabilities and AccessibilityServiceInfo.CAPABILITY_CAN_RETRIEVE_WINDOW_CONTENT) != 0
        }.map { it.resolveInfo.loadLabel(context.packageManager).toString() }
    }

    data class SecurityStatus(
        val isCompromised: Boolean,
        val isRooted: Boolean,
        val isDebuggerAttached: Boolean,
        val isFridaDetected: Boolean,
        val isEmulator: Boolean,
        val accessibilityRisk: RiskLevel,
        val highRiskServices: List<String>
    )
}
