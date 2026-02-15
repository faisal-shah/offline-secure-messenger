plugins {
    kotlin("multiplatform")
    kotlin("plugin.compose")
    id("org.jetbrains.compose")
}

val androidEnabled = rootProject.file("local.properties").let {
    it.exists() && it.readText().contains("sdk.dir")
}

if (androidEnabled) {
    apply(plugin = "com.android.library")
}

kotlin {
    jvm("desktop")

    if (androidEnabled) {
        androidTarget {
            compilations.all {
                kotlinOptions {
                    jvmTarget = "17"
                }
            }
        }
    }

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(compose.runtime)
                implementation(compose.foundation)
                implementation(compose.material3)
                implementation(compose.ui)
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
            }
        }
        val desktopMain by getting {
            dependencies {
                implementation(compose.desktop.currentOs)
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-swing:1.9.0")
            }
        }
        if (androidEnabled) {
            val androidMain by getting {
                dependencies {
                    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
                }
            }
        }
    }
}

if (androidEnabled) {
    extensions.configure<com.android.build.gradle.LibraryExtension> {
        namespace = "com.osmapp.shared"
        compileSdk = 34
        defaultConfig {
            minSdk = 26
        }
        compileOptions {
            sourceCompatibility = JavaVersion.VERSION_17
            targetCompatibility = JavaVersion.VERSION_17
        }
    }
}
