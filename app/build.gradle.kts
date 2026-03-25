plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.ksp)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.google.services)
    // alias(libs.plugins.androidx.room) // Temporarily disabled due to space in path issue
}

android {
    namespace = "com.hariharan.zerokey"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.hariharan.zerokey"
        minSdk = 26 // Autofill requires API 26+
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        
        // Manual Room schema configuration to handle spaces in path
        ksp {
            arg("room.schemaLocation", "$projectDir/schemas")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        compose = true
    }
}

// room {
//    schemaDirectory("schemas")
// }

dependencies {
    // Modular Dependencies
    implementation(project(":domain"))
    implementation(project(":data"))
    implementation(project(":core:crypto"))
    implementation(project(":core:security"))
    implementation(project(":core:common"))
    implementation(project(":core:database"))
    implementation(project(":feature:vault"))
    implementation(project(":feature:autofill"))
    implementation(project(":feature:securitydashboard"))
    implementation(project(":feature:settings"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation("androidx.compose.material:material-icons-extended")
    
    implementation(libs.androidx.security.crypto)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.room.runtime)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.room.ktx)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.compose.runtime.livedata)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.credentials.play.services.auth)
    implementation(libs.googleid)
    
    // Ktor for Breach Monitoring
    implementation("io.ktor:ktor-client-android:3.0.1")
    implementation("io.ktor:ktor-client-logging:3.0.1")
    
    // Argon2 for Secure Key Derivation
    implementation(libs.argon2kt)

    // Tink for ECC (Curve25519) and Hybrid Encryption
    implementation(libs.tink.android)
    
    // Firebase
    implementation(platform(libs.firebase.bom))
    implementation(libs.firebase.auth)
    implementation(libs.firebase.firestore)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)
}
