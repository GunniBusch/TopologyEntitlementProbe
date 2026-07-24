# Network Topology Observation findings

Test date: 2026-07-24

The test app uses the same source and sandbox/network settings in each pair.
The only intentional difference is
`com.apple.developer.networking.topology-observation=true`.
Raw hardware addresses, IP addresses, process names, and signing identifiers
are deliberately omitted from this report.

## iOS 27

Tested on an iPhone running iOS 27.0.

| Observation | Baseline | Entitled |
| --- | ---: | ---: |
| Own interface link addresses | Privacy placeholder | Real addresses |
| IPv4 route entries after the same `/24` warm-up | 14 | 292 |
| IPv4 neighbor entries returned directly | 0 | 254 |
| IPv4 neighbors with resolved link address | 0 | 28 |
| IPv6 route entries | 96 | 169 |
| TCP/UDP/raw PCB sysctls | `EPERM` | `EPERM` |
| Network Statistics provider subscriptions | Denied (`EPERM`; ifnet `ENOTSUP`) | Denied (`EPERM`; ifnet `ENOTSUP`) |
| Live route-socket messages during warm-up | 0 | 0 |

The entitlement exposes the complete route/neighbor view and real link-layer
addresses. The returned route records also contain route class/flags,
interface index, expiry, MTU, RTT, use count, and packets-sent metrics. It does
not unlock the TCP/UDP PCB sysctls or Network Statistics providers on iOS.
Both variants could connect to `com.apple.network.statistics`, but every
provider subscription was rejected (`EPERM` for most providers and `ENOTSUP`
for ifnet).

## iPadOS 26

Tested on an iPad running iPadOS 26.5.2. A second baseline run was made after
the entitled run to remove neighbor-cache warm-up order as a confounder.

Both variants retained privacy-placeholder link addresses. Once the cache was
equally warm, route and neighbor visibility was equivalent. The entitlement
therefore showed no meaningful effect on this iPadOS 26 build.

## macOS 27

Tested with sandboxed macOS apps on macOS 27.0.

| Observation | Baseline | Entitled |
| --- | ---: | ---: |
| Own interface link addresses | Privacy placeholder | Real addresses |
| IPv4 route entries | 9 | 284 after `/24` warm-up |
| IPv4 neighbor records | 0 | 257 |
| IPv6 route entries | 63 | 81 |
| TCP PCB records | 3, all belonging to the probe | 65, across 28 PIDs |
| UDP PCB records | 1, belonging to the probe | 62, across 19 PIDs |
| Raw PCB records | 0 | 1 |
| Network Statistics TCP sources | 62, across 23 PIDs | 55, across 20 PIDs |
| Network Statistics UDP sources | 35, across 10 PIDs | 36, across 11 PIDs |
| Cross-process `libproc` enumeration | Denied | Denied |
| Targeted executable-path lookups for TCP-owner PIDs | 1 of 1 | 26 of 28 |
| Targeted BSD-info lookups for TCP-owner PIDs | 1 of 1 | 18 of 28 |
| Targeted resource-usage lookups for TCP-owner PIDs | 1 of 1 | 1 of 28 |
| Kernel-event socket | Denied | Denied |
| Live route-socket messages during warm-up | 0 | 0 |

The tagged PCB records contain local/remote endpoints, TCP state, UID,
owning/effective PID, socket flags, buffer occupancy, and traffic counters.
They are enough for a `netstat`/partial-`lsof`-style snapshot. Although the
App Sandbox denied `proc_listallpids` in both builds, targeted calls using PIDs
obtained from the entitled PCB records were more permissive: `proc_pidpath`
resolved most executable paths, while `proc_name` and `PROC_PIDTBSDINFO`
resolved a smaller subset. Cross-process resource-usage lookup remained
denied.

The Network Statistics control independently exposed nettop-style per-flow
states, byte/packet counters, interface-type counters, connection attempts,
and owning PIDs to **both** sandboxed macOS variants. A long-lived client could
subscribe to updates; this probe takes a bounded snapshot. It can therefore be
combined with the topology entitlement, but it is not access granted by the
entitlement.

The full route dump adds considerably more than hardware addresses. In the
entitled run it exposed gateway, host, link-layer, interface-scoped, local,
broadcast, multicast, global, and router classifications along with interface
indexes, expiration state, MTU, RTT, use counts, and packets-sent metrics.

## Signing behavior

The live developer server accepted `NETWORK_TOPOLOGY_OBSERVATION` for the
disposable iOS and macOS App IDs.

Automatic iOS signing produced a profile containing the entitlement.
Automatic macOS signing failed because Xcode 27's cached portal-capability
catalog does not contain this capability. Creating a macOS development profile
through the App Store Connect API produced a valid profile containing the
entitlement; manual Xcode signing with that profile succeeded.

## Process-inspection entitlements

The exact topology entitlement remains absent from Apple's public
[Entitlements index](https://developer.apple.com/documentation/bundleresources/entitlements).
No normal developer capability was found whose purpose is to make
`proc_listallpids` work inside the App Sandbox.

Apple's public
[`com.apple.security.cs.debugger`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.cs.debugger)
entitlement governs debugger task-port access, not process-list enumeration.
The restricted
[`com.apple.developer.endpoint-security.client`](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)
entitlement enables an Endpoint Security client/system extension; it is a
separate process-monitoring architecture, not a generic `libproc` permission.

In Apple's open-source
[`bsd/kern/proc_info.c`](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/proc_info.c),
the list-PID syscall passes through the MAC policy hook
`mac_proc_check_proc_info`. The observed `EPERM` is consistent with the
sandbox policy denying that operation. The topology entitlement does not
remove the denial, but its PCB records provide PIDs that can be used for the
targeted lookups measured above.
