# TelBlocker x Mullvad

Goal: one Android app that keeps **all of Mullvad's protections** (DAITA, quantum-resistant
tunnels, multihop, kill switch, lockdown, key rotation) and adds TelBlocker's features on top:

- per-app modes: *Off*, *Telemetry* (block tracking domains), *Block everything*;
- the "Cut off Google services" switch;
- the per-app log of DNS requests and blocked connections.

This fork of [mullvad/mullvadvpn-app](https://github.com/mullvad/mullvadvpn-app)
(GPL-3.0, same license as [TelBlocker](https://github.com/elgaspacho2/TelBlocker)) holds the work.
Upstream code stays on `main` (kept in sync with Mullvad); our changes live on `telblocker`.

## Why a fork of Mullvad, not WireGuard inside TelBlocker

Android allows a single VPN. Re-implementing a WireGuard client in TelBlocker would drop
everything that makes Mullvad's app good. Adding filtering inside Mullvad's app keeps it all,
and the filter sees *all* traffic, so "Block everything" is always complete (no DNS-only
fallback like in TelBlocker's mixed mode).

## Where the code goes (findings from upstream `main`)

| Piece | Upstream location | What we do there |
| --- | --- | --- |
| Tunnel creation | `android/lib/talpid/src/main/kotlin/net/mullvad/talpid/TalpidVpnService.kt` (`configureWith`: MTU, routes, DNS, `addDisallowedApplication` for split tunneling) | Nothing at first. The VPN already captures every app except split-tunneled ones. |
| Packet path, phone → tunnel | `talpid-wireguard/src/gotatun/mod.rs`: the TUN device is wrapped as `SourceFilter<GotaTunDevice>` before GotaTun encrypts packets | Wrap it once more: `AppFilter<SourceFilter<GotaTunDevice>>`. |
| Existing filter to copy | `talpid-wireguard/src/gotatun/source_filter.rs`: an `IpRecv` wrapper that drops packets with an unexpected source address | `AppFilter` is the same pattern: an `IpRecv` wrapper that drops or answers packets. |
| Split tunneling settings | `android/lib/model/.../SplitTunnelSettings.kt`, gRPC `ManagementService.kt` | Model for storing our per-app modes and passing them to the daemon. |

### AppFilter (Rust, `talpid-wireguard/src/gotatun/app_filter.rs`)

1. Read the packet's 5-tuple (protocol, addresses, ports).
2. Find the owning app: Android's `ConnectivityManager.getConnectionOwnerUid()` (allowed for the
   active VPN app), called over JNI **once per new flow** and cached per 5-tuple.
3. App in *Block everything* → drop the packet (fail closed: unknown owner of a blocked
   flow = drop).
4. App in *Telemetry* and the packet is a DNS query (UDP/53 to the tunnel DNS) → parse the
   name; if it's in the blocklist, write an NXDOMAIN answer back to the TUN device and don't
   send the query. Port from TelBlocker's `Dns.kt` and `Packets.kt`.
5. Everything else → passed through to WireGuard unchanged.
6. Each block is reported to the Android side for the log.

## Phases

0. **Fork + build.** Fork upstream, then get an unmodified Android build working in GitHub
   Actions. Mullvad builds in a container (see `building/` and `android/docker/`): Rust, NDK,
   Gradle. This is the riskiest step; nothing else starts before it is green.
1. **Block everything per app** + the Google switch, with a minimal settings screen. This is
   the biggest gain and the simplest filter (drop by UID).
2. **Telemetry mode**: local DNS inspection with TelBlocker's domain list and custom rules.
3. **Log screen** and polish, in the app's Compose design.
4. **Upstream sync**: merge each Mullvad release into the fork; the changes stay small and
   isolated (one Rust file, one Android feature module) to keep merges easy.

## Things to respect

- **Fail closed.** Any error in the filter must drop traffic, never leak it outside the tunnel.
- **Performance.** The UID lookup must stay off the per-packet path (only new flows).
- **Trademark.** "Mullvad" and its logo are trademarks. Fine for a personal build; if this is
  ever published, it needs another app name, icon and package ID.
- **Updates.** A fork of a security app must follow upstream releases closely.
