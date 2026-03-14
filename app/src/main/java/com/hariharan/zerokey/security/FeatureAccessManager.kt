package com.hariharan.zerokey.security

/**
 * Manages access to premium features based on subscription status.
 */
class FeatureAccessManager(private val plan: UserPlan = UserPlan.FREE) {

    enum class UserPlan { FREE, PREMIUM, PRO }

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
        return when (feature) {
            Feature.LOCAL_VAULT, Feature.AUTOFILL, Feature.GENERATOR -> true
            Feature.CLOUD_SYNC, Feature.BREACH_MONITORING, Feature.SECURITY_ANALYTICS -> plan != UserPlan.FREE
            Feature.EMERGENCY_ACCESS, Feature.SECURE_SHARING -> plan == UserPlan.PRO
        }
    }
}
