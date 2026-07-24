import Foundation

@MainActor
final class ProbeViewModel: ObservableObject {
    @Published private(set) var report = "Waiting to run probes…"
    @Published private(set) var isRunning = false
    @Published private(set) var lastRun: Date?

    let variant = Bundle.main.object(forInfoDictionaryKey: "ProbeVariant") as? String ?? "Unknown"

    func run() {
        guard !isRunning else {
            return
        }

        isRunning = true
        Task {
            let result = await ProbeExecutor.run(variant: variant)
            let persisted = ProbeReportStore.persist(result)
            let finalReport = result + "\n" + persisted
            report = finalReport
            lastRun = Date()
            isRunning = false

            print("TOPOLOGY_ENTITLEMENT_PROBE_BEGIN")
            print(finalReport)
            print("TOPOLOGY_ENTITLEMENT_PROBE_END")
        }
    }
}

private enum ProbeReportStore {
    static func persist(_ report: String) -> String {
        do {
            let root = try FileManager.default.url(
                for: .applicationSupportDirectory,
                in: .userDomainMask,
                appropriateFor: nil,
                create: true
            )
            let directory = root.appendingPathComponent(
                "TopologyEntitlementProbe",
                isDirectory: true
            )
            try FileManager.default.createDirectory(
                at: directory,
                withIntermediateDirectories: true
            )
            let destination = directory.appendingPathComponent("probe-report.txt")
            try report.write(to: destination, atomically: true, encoding: .utf8)
            return "probe.swift.report_path=\(destination.path)"
        } catch {
            return "probe.swift.report_write_error=\(error)"
        }
    }
}

private enum ProbeExecutor {
    nonisolated static func run(variant: String) async -> String {
        await Task.detached(priority: .utility) {
            let operatingSystem = ProcessInfo.processInfo.operatingSystemVersionString
#if os(macOS)
            let platform = "macOS"
#elseif os(iOS)
            let platform = "iOS/iPadOS"
#else
            let platform = "unknown"
#endif

            guard let pointer = TEPCopyProbeReport() else {
                return """
                probe.swift.begin
                variant=\(variant)
                platform=\(platform)
                operating_system=\(operatingSystem)
                probe.swift.error=nil-c-report
                probe.swift.end
                """
            }
            defer {
                TEPFreeProbeReport(pointer)
            }

            return """
            probe.swift.begin
            variant=\(variant)
            expected_topology_entitlement=\(variant == "Entitled" ? "true" : "false")
            platform=\(platform)
            operating_system=\(operatingSystem)
            \(String(cString: pointer))
            probe.swift.end
            """
        }.value
    }
}
