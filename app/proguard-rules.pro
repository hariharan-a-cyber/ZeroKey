# Standard Android keep rules
-keepattributes *Annotation*, InnerClasses, Signature, Exceptions
-dontwarn javax.annotation.**

# Keep Room entities and DAOs (paths updated for current modular layout)
-keep class com.hariharan.zerokey.core.database.** { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }

# Keep data models used with kotlinx.serialization
-keep class com.hariharan.zerokey.data.model.** { *; }
-keep class com.hariharan.zerokey.sync.** { *; }
-keep class com.hariharan.zerokey.sharing.** { *; }

# Keep Firebase / Firestore models (reflection-based mapping)
-keep class com.google.firebase.** { *; }
-keepclassmembers class * {
    @com.google.firebase.firestore.PropertyName <fields>;
}

# Keep kotlinx.serialization machinery
-dontnote kotlinx.serialization.AnnotationsKt
-keep class kotlinx.serialization.** { *; }
-keepclassmembers class **$Companion {
    kotlinx.serialization.KSerializer serializer(...);
}

# Keep all crypto + master password classes (reflection points, JNI bridges)
-keep class com.hariharan.zerokey.core.crypto.** { *; }
-keep class com.hariharan.zerokey.core.security.MasterPasswordManager { *; }
-keep class com.lambdapioneer.argon2kt.** { *; }
-keep class com.google.crypto.tink.** { *; }

# Keep Firestore document field accessors
-keepclassmembers class com.hariharan.zerokey.** {
    <fields>;
}

# Hilt
-keep class dagger.hilt.** { *; }
-keepnames @dagger.hilt.android.HiltAndroidApp class *

# Ktor client (used by DigitalAssetLinksVerifier)
-keep class io.ktor.** { *; }
-dontwarn io.ktor.**
