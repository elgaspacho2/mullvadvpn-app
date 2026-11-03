plugins {
    alias(libs.plugins.mullvad.android.library)
    alias(libs.plugins.mullvad.android.library.feature.impl)
    alias(libs.plugins.mullvad.android.library.compose)
}

android { namespace = "net.mullvad.mullvadvpn.feature.telblocker.impl" }

dependencies {
    implementation(projects.lib.feature.telblocker.api)
    implementation(projects.lib.talpid)

    implementation(libs.kotlinx.coroutines.android)
}
