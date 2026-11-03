package net.mullvad.mullvadvpn.feature.telblocker.impl

import android.Manifest
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.drawable.Drawable
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyListScope
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.produceState
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.lifecycle.compose.dropUnlessResumed
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import net.mullvad.mullvadvpn.core.Navigator
import net.mullvad.mullvadvpn.lib.common.compose.unlessIsDetail
import net.mullvad.mullvadvpn.lib.ui.component.ScaffoldWithSmallTopBar
import net.mullvad.mullvadvpn.lib.ui.component.button.NavigateBackIconButton
import net.mullvad.mullvadvpn.lib.ui.component.listitem.IconState
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SplitTunnelingListItem
import net.mullvad.mullvadvpn.lib.ui.component.listitem.SwitchListItem
import net.mullvad.mullvadvpn.lib.ui.designsystem.Position
import net.mullvad.mullvadvpn.lib.ui.theme.Dimens
import net.mullvad.talpid.telblocker.TelBlockerRules

/** An app that can use the network. */
private class AppEntry(
    val packageName: String,
    val label: String,
    val icon: Drawable?,
    val isSystem: Boolean,
)

private class AppList(val apps: List<AppEntry>, val installedGoogleServices: List<String>)

@Composable
fun TelBlocker(navigator: Navigator) {
    val context = LocalContext.current
    remember(context) { TelBlockerRules.init(context) }
    val blocked by TelBlockerRules.blockedPackages.collectAsState()
    val appList by
        produceState<AppList?>(initialValue = null, context) {
            value = withContext(Dispatchers.IO) { loadApps(context) }
        }

    TelBlockerScreen(
        appList = appList,
        blocked = blocked,
        onSetBlocked = { packages, block -> TelBlockerRules.setBlocked(context, packages, block) },
        onBackClick = dropUnlessResumed { navigator.goBack() },
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun TelBlockerScreen(
    appList: AppList?,
    blocked: Set<String>,
    onSetBlocked: (packages: Collection<String>, block: Boolean) -> Unit,
    onBackClick: () -> Unit,
) {
    var showSystemApps by rememberSaveable { mutableStateOf(false) }
    var confirmGoogle by rememberSaveable { mutableStateOf(false) }

    ScaffoldWithSmallTopBar(
        appBarTitle = stringResource(R.string.telblocker_title),
        navigationIcon = {
            unlessIsDetail { NavigateBackIconButton(onNavigateBack = onBackClick) }
        },
    ) { modifier ->
        LazyColumn(
            modifier = modifier.padding(horizontal = Dimens.sideMarginNew),
            state = rememberLazyListState(),
        ) {
            item {
                Text(
                    text = stringResource(R.string.telblocker_description),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(bottom = Dimens.cellVerticalSpacing),
                )
            }
            if (appList == null) {
                item { Text(text = stringResource(R.string.telblocker_loading)) }
                return@LazyColumn
            }

            val google = appList.installedGoogleServices
            if (google.isNotEmpty()) {
                item {
                    SwitchListItem(
                        title = stringResource(R.string.telblocker_google_services),
                        isToggled = blocked.containsAll(google),
                        onCellClicked = { block ->
                            if (block) confirmGoogle = true else onSetBlocked(google, false)
                        },
                    )
                }
                item { Caption(stringResource(R.string.telblocker_google_services_details)) }
            }
            item {
                SwitchListItem(
                    title = stringResource(R.string.telblocker_show_system_apps),
                    isToggled = showSystemApps,
                    onCellClicked = { showSystemApps = it },
                )
            }
            item { Spacer(modifier = Modifier.height(Dimens.cellVerticalSpacing)) }

            val (blockedApps, otherApps) = appList.apps.partition { it.packageName in blocked }
            appSection(R.string.telblocker_blocked_apps, blockedApps, isBlocked = true, onSetBlocked)
            appSection(
                R.string.telblocker_all_apps,
                otherApps.filter { showSystemApps || !it.isSystem },
                isBlocked = false,
                onSetBlocked,
            )
        }
    }

    if (confirmGoogle && appList != null) {
        AlertDialog(
            onDismissRequest = { confirmGoogle = false },
            title = { Text(stringResource(R.string.telblocker_google_confirm_title)) },
            text = { Text(stringResource(R.string.telblocker_google_confirm_message)) },
            confirmButton = {
                TextButton(
                    onClick = {
                        confirmGoogle = false
                        onSetBlocked(appList.installedGoogleServices, true)
                    }
                ) {
                    Text(stringResource(R.string.telblocker_google_confirm_ok))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmGoogle = false }) {
                    Text(stringResource(R.string.telblocker_cancel))
                }
            },
        )
    }
}

private fun LazyListScope.appSection(
    titleRes: Int,
    apps: List<AppEntry>,
    isBlocked: Boolean,
    onSetBlocked: (packages: Collection<String>, block: Boolean) -> Unit,
) {
    if (apps.isEmpty()) return
    item(key = "header-$isBlocked") {
        Text(
            text = stringResource(titleRes),
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.fillMaxWidth().padding(vertical = Dimens.smallPadding),
        )
    }
    items(items = apps, key = { "${it.packageName}-$isBlocked" }) { app ->
        SplitTunnelingListItem(
            title = AnnotatedString(app.label),
            iconState = app.icon?.let { IconState.Icon(it) } ?: IconState.NoIcon,
            isSelected = isBlocked,
            position = Position.Middle,
            onCellClicked = { onSetBlocked(listOf(app.packageName), !isBlocked) },
        )
    }
    item(key = "spacer-$isBlocked") { Spacer(modifier = Modifier.height(Dimens.cellVerticalSpacing)) }
}

@Composable
private fun Caption(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodySmall,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = Dimens.smallPadding, bottom = Dimens.cellVerticalSpacing),
    )
}

/** Apps that hold the INTERNET permission, sorted by name. */
private fun loadApps(context: Context): AppList {
    val pm = context.packageManager
    val apps =
        pm.getInstalledApplications(0)
            .filter {
                it.packageName != context.packageName &&
                    pm.checkPermission(Manifest.permission.INTERNET, it.packageName) ==
                        PackageManager.PERMISSION_GRANTED
            }
            .map {
                AppEntry(
                    packageName = it.packageName,
                    label = it.loadLabel(pm).toString(),
                    icon = runCatching { it.loadIcon(pm) }.getOrNull(),
                    isSystem = (it.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
                )
            }
            .sortedBy { it.label.lowercase() }
    val installed = apps.mapTo(mutableSetOf()) { it.packageName }
    return AppList(apps, TelBlockerRules.GOOGLE_SERVICES.filter { it in installed })
}
