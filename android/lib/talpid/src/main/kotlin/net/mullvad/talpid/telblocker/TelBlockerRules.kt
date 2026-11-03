package net.mullvad.talpid.telblocker

import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.os.Process
import co.touchlab.kermit.Logger
import java.net.InetAddress
import java.net.InetSocketAddress
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * TelBlocker: the apps cut off from the network ("block everything").
 *
 * The list is stored in shared preferences and read by the tunnel through
 * [isConnectionAllowed], which `TalpidVpnService` exposes to the Rust packet filter. The UI and
 * the VPN service run in the same process, so changes apply right away.
 */
object TelBlockerRules {
    /** Google Play Services, Google Services Framework and the Play Store. */
    val GOOGLE_SERVICES =
        listOf("com.google.android.gms", "com.google.android.gsf", "com.android.vending")

    private const val PREFS_NAME = "telblocker"
    private const val KEY_BLOCKED_PACKAGES = "block_all_packages"

    private val _blockedPackages = MutableStateFlow<Set<String>>(emptySet())
    val blockedPackages: StateFlow<Set<String>> = _blockedPackages.asStateFlow()

    @Volatile private var blockedUids: Set<Int> = emptySet()
    @Volatile private var prefs: SharedPreferences? = null
    @Volatile private var packageManager: PackageManager? = null

    @Synchronized
    fun init(context: Context) {
        if (prefs != null) return
        val appContext = context.applicationContext
        packageManager = appContext.packageManager
        prefs = appContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        load()
    }

    fun setBlocked(context: Context, packages: Collection<String>, blocked: Boolean) {
        init(context)
        val current = _blockedPackages.value
        val updated = if (blocked) current + packages else current - packages.toSet()
        prefs?.edit()?.putStringSet(KEY_BLOCKED_PACKAGES, updated)?.apply()
        load()
    }

    /** Re-reads the list and the apps' UIDs, which change when an app is reinstalled. */
    @Synchronized
    fun load() {
        val packages = prefs?.getStringSet(KEY_BLOCKED_PACKAGES, null)?.toSet() ?: emptySet()
        val pm = packageManager
        blockedUids =
            if (pm == null) emptySet()
            else
                packages.mapNotNullTo(mutableSetOf()) {
                    try {
                        pm.getPackageUid(it, 0)
                    } catch (_: PackageManager.NameNotFoundException) {
                        null
                    }
                }
        _blockedPackages.value = packages
    }

    /**
     * Whether a connection may enter the tunnel. Blocked when it belongs to a blocked app. A
     * connection whose app can't be found (it closed meanwhile) is let through: it can't be tied
     * to a blocked app. Any other failure blocks it.
     */
    fun isConnectionAllowed(
        connectivityManager: ConnectivityManager,
        protocol: Int,
        sourceIp: ByteArray,
        sourcePort: Int,
        destinationIp: ByteArray,
        destinationPort: Int,
    ): Boolean {
        val uids = blockedUids
        if (uids.isEmpty()) return true
        return try {
            val uid =
                connectivityManager.getConnectionOwnerUid(
                    protocol,
                    InetSocketAddress(InetAddress.getByAddress(sourceIp), sourcePort),
                    InetSocketAddress(InetAddress.getByAddress(destinationIp), destinationPort),
                )
            uid == Process.INVALID_UID || uid !in uids
        } catch (@Suppress("TooGenericExceptionCaught") e: Exception) {
            Logger.w("TelBlocker: blocking connection, owner lookup failed", e)
            false
        }
    }
}
