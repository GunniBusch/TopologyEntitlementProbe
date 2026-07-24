import SwiftUI

@main
struct TopologyEntitlementProbeApp: App {
    @StateObject private var model = ProbeViewModel()

    var body: some Scene {
        WindowGroup {
            ContentView(model: model)
        }
    }
}
