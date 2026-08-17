import SwiftUI
import NetworkExtension

@main
struct ChimeraVPNApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

/// UI-facing model that wraps NEVPNManager. Kept as an ObservableObject so
/// the SwiftUI view can be a pure, stateless presentation of these values.
final class VPNViewModel: ObservableObject {
    @Published var serverAddr = "127.0.0.1:4789"
    @Published var seedHex = ""
    @Published var generation = 0
    @Published var pskHex = ""
    @Published var tunIP = "10.99.0.2"
    @Published var status = "未连接"
    @Published var isBusy = false
    @Published var servers: [SavedServer] = []
    @Published var logLines: [String] = []
    @Published var trafficText = "↑ 0 B    ↓ 0 B"

    private let vpnManager = NEVPNManager.shared()
    private let defaults = UserDefaults.standard
    private var ticker: Timer?

    init() {
        restoreForm()
        restoreServers()
        ticker = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refreshTunnelShare()
            }
        }
        NotificationCenter.default.addObserver(
            forName: NSNotification.Name.NEVPNStatusDidChange,
            object: vpnManager.connection,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.refreshStatus()
            }
        }
        loadConfiguration()
    }

    /// Load the existing VPN configuration from Preferences, if any, and show
    /// its current connection status.
    func loadConfiguration() {
        vpnManager.loadFromPreferences { [weak self] error in
            Task { @MainActor in
                guard let self = self else { return }
                if let error {
                    self.status = "加载配置失败: \(error.localizedDescription)"
                    return
                }
                self.refreshStatus()
            }
        }
    }

    func connect() {
        guard !serverAddr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            status = "请填写服务器地址"
            return
        }
        let seed = seedHex.trimmingCharacters(in: .whitespacesAndNewlines)
        let psk = pskHex.trimmingCharacters(in: .whitespacesAndNewlines)
        guard seed.count == 64, psk.count == 64 else {
            status = "seed 和 PSK 都必须是 64 位十六进制（32 字节）"
            return
        }

        isBusy = true
        status = "正在准备配置..."
        persistForm()
        rememberCurrent()

        let protocolConfiguration = NETunnelProviderProtocol()
        protocolConfiguration.providerBundleIdentifier = "com.chimera.vpn.tunnel"
        protocolConfiguration.serverAddress = serverAddr
        protocolConfiguration.disconnectOnSleep = false
        protocolConfiguration.providerConfiguration = [
            "serverAddr": serverAddr,
            "seedHex": seedHex,
            "generation": generation,
            "pskHex": pskHex,
            "tunIP": tunIP
        ]

        vpnManager.loadFromPreferences { [weak self] error in
            guard let self = self else { return }

            if let error {
                Task { @MainActor in
                    self.status = "加载系统 VPN 配置失败: \(error.localizedDescription)"
                    self.isBusy = false
                }
                return
            }

            self.vpnManager.protocolConfiguration = protocolConfiguration
            self.vpnManager.isEnabled = true

            self.vpnManager.saveToPreferences { [weak self] error in
                Task { @MainActor in
                    guard let self else { return }
                    if let error {
                        self.status = "保存 VPN 配置失败: \(error.localizedDescription)"
                        self.isBusy = false
                        return
                    }

                    do {
                        try self.vpnManager.connection.startVPNTunnel()
                        self.status = "正在连接..."
                    } catch {
                        self.status = "启动隧道失败: \(error.localizedDescription)"
                    }
                    self.isBusy = false
                }
            }
        }
    }

    func disconnect() {
        vpnManager.connection.stopVPNTunnel()
        refreshStatus()
    }

    private func refreshStatus() {
        switch vpnManager.connection.status {
        case .invalid:
            status = "未配置"
        case .disconnected:
            status = "未连接"
        case .connecting:
            status = "连接中..."
        case .connected:
            status = "已连接"
        case .reasserting:
            status = "正在重新连接..."
        case .disconnecting:
            status = "断开中..."
        @unknown default:
            status = "未知状态"
        }
    }

    private func persistForm() {
        defaults.set(serverAddr, forKey: "serverAddr")
        defaults.set(seedHex, forKey: "seedHex")
        defaults.set(generation, forKey: "generation")
        defaults.set(pskHex, forKey: "pskHex")
        defaults.set(tunIP, forKey: "tunIP")
    }

    private func restoreForm() {
        if let v = defaults.string(forKey: "serverAddr"), !v.isEmpty { serverAddr = v }
        if let v = defaults.string(forKey: "seedHex") { seedHex = v }
        if defaults.object(forKey: "generation") != nil { generation = defaults.integer(forKey: "generation") }
        if let v = defaults.string(forKey: "pskHex") { pskHex = v }
        if let v = defaults.string(forKey: "tunIP"), !v.isEmpty { tunIP = v }
    }

    private func restoreServers() {
        guard let data = defaults.data(forKey: "servers"),
              let list = try? JSONDecoder().decode([SavedServer].self, from: data) else { return }
        servers = list
    }

    private func persistServers() {
        if let data = try? JSONEncoder().encode(servers) {
            defaults.set(data, forKey: "servers")
        }
    }

    func rememberCurrent() {
        let addr = serverAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !addr.isEmpty else { return }
        if servers.contains(where: { $0.addr.caseInsensitiveCompare(addr) == .orderedSame }) {
            persistServers()
            return
        }
        servers.insert(SavedServer(name: addr, addr: addr), at: 0)
        persistServers()
    }

    func forget(_ server: SavedServer) {
        servers.removeAll { $0.addr.caseInsensitiveCompare(server.addr) == .orderedSame }
        persistServers()
    }

    private func refreshTunnelShare() {
        logLines = TunnelShare.logs()
        let t = TunnelShare.traffic()
        trafficText = "↑ \(TunnelShare.formatBytes(t.sent))    ↓ \(TunnelShare.formatBytes(t.recv))"
        refreshStatus()
    }
}

struct SavedServer: Codable, Identifiable, Hashable {
    var name: String
    var addr: String
    var id: String { addr.lowercased() }
}

struct ContentView: View {
    @StateObject private var model = VPNViewModel()

    var body: some View {
        NavigationView {
            Form {
                Section("服务器配置") {
                    TextField("服务器地址 (host:port)", text: $model.serverAddr)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)

                    TextField("Seed (十六进制)", text: $model.seedHex)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)

                    TextField("Generation", value: $model.generation, format: .number)
                        .keyboardType(.numberPad)

                    TextField("本机 TUN 地址（服务端未分配时回退）", text: $model.tunIP)
                    SecureField("PSK (64 hex，必填)", text: $model.pskHex)
                        .textInputAutocapitalization(.never)
                        .disableAutocorrection(true)
                }

                Section("流量") {
                    Text(model.trafficText)
                        .font(.system(.body, design: .monospaced))
                }

                Section("节点") {
                    if model.servers.isEmpty {
                        Text("还没有保存的入口。连接成功后会自动记下当前 host:port。")
                            .foregroundColor(.secondary)
                    }
                    ForEach(model.servers) { server in
                        HStack {
                            Button(action: { model.serverAddr = server.addr }) {
                                VStack(alignment: .leading) {
                                    Text(server.name)
                                    Text(server.addr)
                                        .font(.caption)
                                        .foregroundColor(.secondary)
                                }
                            }
                            Spacer()
                            Button("删除") {
                                model.forget(server)
                            }
                            .foregroundColor(.red)
                        }
                    }
                    Button("保存当前入口") {
                        model.rememberCurrent()
                    }
                }

                Section("状态") {
                    HStack {
                        Text(model.status)
                        Spacer()
                        if model.isBusy {
                            ProgressView()
                        }
                    }
                }

                Section {
                    Button("连接") {
                        model.connect()
                    }
                    .disabled(model.isBusy)

                    Button("断开") {
                        model.disconnect()
                    }
                }

                Section("日志") {
                    ScrollView {
                        Text(model.logLines.isEmpty ? "隧道日志会写到 App Group。扩展未签名或未开 group 时这里是空的。" : model.logLines.joined(separator: "\n"))
                            .font(.system(.footnote, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .textSelection(.enabled)
                    }
                    .frame(minHeight: 160)
                }
            }
            .navigationTitle("Chimera VPN")
        }
    }
}
