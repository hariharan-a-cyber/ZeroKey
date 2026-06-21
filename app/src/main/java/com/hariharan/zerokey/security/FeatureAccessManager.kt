package com.hariharan.zerokey.security

import kotlinx.coroutines.flow.StateFlow

/**
 * Manages access to premium features based on subscription status.
 */
class FeatureAccessManager(private val isPremiumFlow: StateFlow<Boolean>) {

    enum class Feature {
        CLOUD_SYNC,
        BREACH_MONITORING,
        SECURITY_ANALYTICS,
        EMERGENCY_ACCESS,
        SECURE_SHARING,
        LOCAL_VAULT,
        AUTOFILL,
        GENERATOR
    }

    /**
     * Returns true if the current plan has access to the given feature.
     */
    fun hasAccess(feature: Feature): Boolean {
        // BYPASS: For current development/release phase, all features are free.
        return true
    }
}
