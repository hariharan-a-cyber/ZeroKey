pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "zerokey"
include(":app")
include(":core:crypto")
include(":core:security")
include(":core:database")
include(":core:common")
include(":data")
include(":domain")
include(":feature:vault")
include(":feature:autofill")
include(":feature:securitydashboard")
include(":feature:settings")
