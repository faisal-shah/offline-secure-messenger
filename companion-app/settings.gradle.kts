pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

@Suppress("UnstableApiUsage")
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "companion-app"
include(":shared")
include(":desktopApp")

val localPropsFile = file("local.properties")
val hasAndroidSdk = localPropsFile.exists() && localPropsFile.readText().contains("sdk.dir")
if (hasAndroidSdk) {
    include(":androidApp")
}
