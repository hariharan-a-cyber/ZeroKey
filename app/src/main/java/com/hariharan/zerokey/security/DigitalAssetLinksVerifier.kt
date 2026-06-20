package com.hariharan.zerokey.security

import android.util.LruCache
import com.hariharan.zerokey.core.common.PrivacyLogger
import io.ktor.client.HttpClient
import io.ktor.client.engine.android.Android
import io.ktor.client.request.get
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/**
 * Verifies a website's Digital Asset Links file claims the given Android package.
 *
 * SECURITY: this implementation FAILS CLOSED. Missing / unreachable assetlinks.json
 * is NOT treated as verified. The previous fail-open behavior let any attacker
 * domain that returned 404 / 5xx / timeout claim verified status, defeating the
 * point of the check.
 */
class DigitalAssetLinksVerifier {

    private val client = HttpClient(Android)

    private data class CacheEntry(val verified: Boolean, val expiresAt: Long)
    private val cache = LruCache<String, CacheEntry>(100)

    companion object {
        // Positive results are cached longer; negative/error results retry sooner
        // so a single network blip doesn't permanently brand a domain as suspect.
        private const val POSITIVE_TTL_MS = 24L * 60 * 60 * 1000
        private const val NEGATIVE_TTL_MS = 5L * 60 * 1000
    }

    suspend fun verify(webDomain: String, packageName: String): Boolean {
        val cacheKey = "$webDomain|$packageName"
        cache.get(cacheKey)?.let { entry ->
            if (System.currentTimeMillis() < entry.expiresAt) return entry.verified
            cache.remove(cacheKey)
        }

        val verified = try {
            val url = "https://$webDomain/.well-known/assetlinks.json"
            PrivacyLogger.d("AssetLinksVerifier", "Fetching assetlinks")

            val response: HttpResponse = client.get(url)
            if (response.status.value != 200) {
                false
            } else {
                val body = response.bodyAsText()
                val jsonArray = Json.parseToJsonElement(body).jsonArray
                jsonArray.any { element ->
                    val target = element.jsonObject["target"]?.jsonObject ?: return@any false
                    val namespace = target["namespace"]?.jsonPrimitive?.content
                    val targetPackage = target["package_name"]?.jsonPrimitive?.content
                    namespace == "android_app" && targetPackage == packageName
                }
            }
        } catch (e: Exception) {
            PrivacyLogger.w("AssetLinksVerifier", "Verification error (treated as unverified): ${e.message}")
            false
        }

        val ttl = if (verified) POSITIVE_TTL_MS else NEGATIVE_TTL_MS
        cache.put(cacheKey, CacheEntry(verified, System.currentTimeMillis() + ttl))
        return verified
    }
}
