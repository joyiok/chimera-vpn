plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// bind.aar 由 ./build-android-core.sh 生成。文件不存在时项目仍可编译，
// 运行时会通过 GoBind 反射给出明确错误。
val bindAarExists = file("libs/bind.aar").exists()

android {
    namespace = "com.chimera.vpn"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.chimera.vpn"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"
    }

    buildFeatures {
        viewBinding = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.6")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.8.1")

    if (bindAarExists) {
        implementation(files("libs/bind.aar"))
    }
}
