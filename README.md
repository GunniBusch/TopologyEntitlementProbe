# Topology Entitlement Probe

This isolated experiment compares the behavior of:

- `com.apple.developer.networking.topology-observation` builds
- otherwise equivalent baseline builds without that entitlement

There are separate iOS/iPadOS and sandboxed macOS targets. The probe checks:

- local IPv4, IPv6, and link-layer interface visibility through `getifaddrs`
- IPv4 and IPv6 neighbor-cache visibility with `NET_RT_FLAGS` and `NET_RT_FLAGS_PRIV`
- IPv4/IPv6 route dumps, route flags, and interface-list sysctls
- route and kernel-event socket creation
- TCP/UDP/raw PCB sysctl visibility, including tagged socket-table metadata on macOS
- system process/socket enumeration and TCP state through `libproc`

The `libproc` header explicitly describes those interfaces as private and
subject to change. Their inclusion here is investigative and does not imply
that they are suitable for App Store production code.

See [RESULTS.md](RESULTS.md) for the sanitized A/B results and the
public-documentation check.

The repository deliberately contains no development-team identifier,
provisioning profile, certificate, device identifier, raw hardware address,
raw IP address, or captured process name.

## Targets

- `TopologyProbeIOSEntitled`
- `TopologyProbeIOSBaseline`
- `TopologyProbeMacEntitled`
- `TopologyProbeMacBaseline`

## Generate

Requirements:

- Xcode 27 or newer for the tested OS 27 behavior
- [XcodeGen](https://github.com/yonaskolb/XcodeGen) 2.45 or newer
- an Apple Developer team with the **Network Topology Observation** capability
  enabled for the entitled target's App ID

Replace the four `com.example` bundle identifiers in `project.yml` with unique
identifiers owned by your team, then generate the project:

```sh
xcodegen generate
```

Select your development team in Xcode for the targets you want to run. The
baseline targets need no topology capability. The entitled targets require a
provisioning profile containing:

```xml
<key>com.apple.developer.networking.topology-observation</key>
<true/>
```

Automatic iOS signing worked during this test. Xcode 27's cached capability
catalog did not recognize this capability for automatic macOS signing, so the
macOS entitled target required a development profile created through the
developer service and selected manually in Xcode.

## macOS run loop

After replacing the example bundle identifiers and configuring signing, the
default run action builds the entitled macOS target:

```sh
./script/build_and_run.sh
```

To build the baseline instead:

```sh
TOPOLOGY_PROBE_SCHEME=TopologyProbeMacBaseline ./script/build_and_run.sh
```

The entitlement produced a meaningful behavior change on iOS 27 and macOS 27
in this experiment. It did not produce a meaningful change on the tested
iPadOS 26.5.2 device.
