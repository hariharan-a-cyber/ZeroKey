package com.hariharan.zerokey.security

import com.hariharan.zerokey.core.common.PrivacyLogger
import android.util.LruCache
import io.ktor.client.*
import io.ktor.client.engine.android.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import kotlinx.serialization.json.*

/**
 * Verifies Android App Links (Digital Asset Links).
 * Fetches /.well-known/assetlinks.json and checks package name.
 */
class DigitalAssetLinksVerifier {

    private val client = HttpClient(Android)
    private val cache = LruCache<String, Boolean>(100)

    suspend fun verify(webDomain: String, packageName: String): Boolean {
        val cacheKey = "$webDomain|$packageName"
        cache.get(cacheKey)?.let { return it }

        return try {
            val url = "https://$webDomain/.well-known/assetlinks.json"
            PrivacyLogger.d("AssetLinksVerifier", "Fetching assetlinks from $url")
            
            val response: HttpResponse = client.get(url)
            if (response.status.value != 200) return true // Fail open if file doesn't exist

            val body = response.bodyAsText()
            val jsonArray = Json.parseToJsonElement(body).jsonArray
            
            jsonArray.any { element ->
                val target = element.jsonObject["target"]?.jsonObject ?: return@any false
                val namespace = target["namespace"]?.jsonPrimitive?.content
                val targetPackage = target["package_name"]?.jsonPrimitive?.content
                
                namespace == "android_app" && targetPackage == packageName
            }.also {
                cache.put(cacheKey, it)
            }
        } catch (e: Exception) {
            PrivacyLogger.w("AssetLinksVerifier", "Verification error for $webDomain: ${e.message}")
            true // Fail open for general domains
        }
    }
}
