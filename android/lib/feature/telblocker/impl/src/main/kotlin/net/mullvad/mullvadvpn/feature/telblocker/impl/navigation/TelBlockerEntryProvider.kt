package net.mullvad.mullvadvpn.feature.telblocker.impl.navigation

import androidx.navigation3.runtime.EntryProviderScope
import net.mullvad.mullvadvpn.core.NavKey2
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.core.animation.slideInHorizontalTransition
import net.mullvad.mullvadvpn.core.scene.ListDetailSceneStrategy
import net.mullvad.mullvadvpn.feature.telblocker.api.TelBlockerNavKey
import net.mullvad.mullvadvpn.feature.telblocker.impl.TelBlocker

fun EntryProviderScope<NavKey2>.telBlockerEntry(navigator: Navigator) {
    entry<TelBlockerNavKey>(
        metadata = ListDetailSceneStrategy.detailPane() + slideInHorizontalTransition()
    ) {
        TelBlocker(navigator = navigator)
    }
}
