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
| IPv4 route entries after the same `/24` warm-up | 14 | 301 |
| IPv4 neighbor entries returned directly | 0 | 254 |
| IPv4 neighbors with resolved link address | 0 | 28 |
| IPv6 route entries | 96 | 169 |
| TCP/UDP/raw PCB sysctls | `EPERM` | `EPERM` |

The entitlement exposes the complete route/neighbor view and real link-layer
addresses. It does not unlock the TCP/UDP PCB sysctls on iOS.

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
| IPv4 route entries | 13–14 | About 400 after `/24` warm-up |
| IPv4 neighbor records | 0 | 257 |
| IPv6 route entries | 63 | 81 |
| Legacy TCP PCB records | 0 | 78 |
| Legacy UDP PCB records | 0 | 66 |
| Raw PCB records | 0 | 1 |
| Tagged TCP PCB records | 0 | 78 |
| Tagged UDP PCB records | 0 | 66 |
| Distinct PIDs in tagged TCP records | 0 | 32 |
| TCP states observed | None | 14 listening, 64 established |
| Cross-process `libproc` enumeration | Denied | Denied |
| Kernel-event socket | Denied | Denied |

The tagged PCB records contain local/remote endpoints, TCP state, UID,
owning/effective PID, socket flags, buffer occupancy, and traffic counters.
Process names were resolvable for 22 of the 32 TCP PIDs and 10 of the 18 UDP
PIDs in this run. This is enough for a `netstat`/partial-`lsof`-style snapshot.
It is not the streaming per-flow telemetry used by `nettop`, and the
entitlement does not grant general cross-process `libproc` access.

## Signing behavior

The live developer server accepted `NETWORK_TOPOLOGY_OBSERVATION` for the
disposable iOS and macOS App IDs.

Automatic iOS signing produced a profile containing the entitlement.
Automatic macOS signing failed because Xcode 27's cached portal-capability
catalog does not contain this capability. Creating a macOS development profile
through the App Store Connect API produced a valid profile containing the
entitlement; manual Xcode signing with that profile succeeded.

## Public-documentation filter

The exact entitlement is absent from Apple's public Entitlements index, and
searches of Apple's public developer documentation returned no page for:

- `com.apple.developer.networking.topology-observation`
- `com.apple.developer.cross-architecture-support`
- `com.apple.developer.cross-architecture-support-unmanaged`
- `com.apple.developer.model-delegation`

Two server-exposed capability labels meet the same public-documentation filter:

- **Network Topology Observation** — confirmed requestable and runtime-tested.
- **Cross-architecture Compatibility Framework** — visible in the live
  developer portal; the likely corresponding entitlement keys occur in the
  macOS 27 kernel, but the mapping, behavior, and third-party provisioning
  remain unverified.

`com.apple.developer.model-delegation` is a separate OS-private finding, not a
confirmed developer-portal capability. It appears in an Apple generative
partner extension and in Xcode 27's link-metadata tooling, suggesting model
provider delegation into system experiences. It is not shown as a requestable
capability.

Items such as Accessory Access USB, FSKit mounting, Suggested Actions, Trust
Insights, Background Inference, EnergyKit LoadEvents, and Media Device
Extension are excluded from the undocumented list because Apple now documents
them publicly or declares them in the public SDK.
