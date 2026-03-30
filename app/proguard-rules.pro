# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
#-renamesourcefileattribute SourceFile

# Keep Room entities and DAOs
-keep class com.hariharan.zerokey.data.database.** { *; }
-keep @androidx.room.Entity class * { *; }
-keep @androidx.room.Dao class * { *; }

# Keep data models used with kotlinx.serialization
-keep class com.hariharan.zerokey.data.model.** { *; }
-keep class com.hariharan.zerokey.sync.** { *; }

# Keep Firebase models (Firestore uses reflection)
-keep class com.google.firebase.** { *; }
-keepattributes Signature
-keepattributes *Annotation*

# Keep Kotlin serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keep class kotlinx.serialization.** { *; }

# Keep security classes (don't obfuscate crypto logic names — it breaks references)
-keep class com.hariharan.zerokey.security.MasterPasswordManager { *; }
-keep class com.hariharan.zerokey.security.EncryptionManager { *; }
