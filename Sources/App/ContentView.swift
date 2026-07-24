import SwiftUI

struct ContentView: View {
    @ObservedObject var model: ProbeViewModel

    var body: some View {
        NavigationStack {
            List {
                Section("Build") {
                    LabeledContent("Variant", value: model.variant)
                    if let lastRun = model.lastRun {
                        LabeledContent("Last Run", value: lastRun.formatted())
                    }
                }

                Section {
                    ScrollView([.horizontal, .vertical]) {
                        Text(model.report)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                            .frame(maxWidth: .infinity, alignment: .topLeading)
                            .padding(.vertical, 4)
                    }
                    .frame(minHeight: 420)
                } header: {
                    Text("Probe Report")
                } footer: {
                    Text("The libproc checks use SDK-shipped but explicitly private/unsupported process-inspection interfaces. This app is a diagnostic experiment, not production code.")
                }
            }
            .navigationTitle("Topology Entitlement Probe")
            .toolbar {
                ToolbarItemGroup {
                    ShareLink(item: model.report) {
                        Label("Share Report", systemImage: "square.and.arrow.up")
                    }
                    .disabled(model.isRunning)

                    Button {
                        model.run()
                    } label: {
                        Label("Run Probes", systemImage: "play.fill")
                    }
                    .disabled(model.isRunning)
                }
            }
            .task {
                if model.lastRun == nil {
                    model.run()
                }
            }
        }
    }
}

#Preview {
    ContentView(model: ProbeViewModel())
}
