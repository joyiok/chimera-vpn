import Foundation
import NetworkExtension
import os.log

/// NEPacketTunnelProvider entry point for the ChimeraVPN tunnel target.
///
/// The App saves a `NETunnelProviderProtocol` with these `providerConfiguration` keys:
/// - `serverAddr`: server address in host:port form
/// - `seedHex`: seed for the Chimera protocol
/// - `generation`: generation number for the Chimera protocol
/// - `pskHex`: optional pre-shared key (empty string when unused)
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.chimera.vpn.tunnel", category: "PacketTunnelProvider")

    /// Serial queue used by the writer loop. `GoBind.receive` blocks until a
    /// packet is available, so it must never run on the main thread.
    private let writerQueue = DispatchQueue(label: "com.chimera.vpn.tunnel.writer", qos: .utility)

    /// Session handle returned by GoBind.start. -1 means "no session".
    private var handle: Int64 = -1

    /// Set to false by `stopTunnel` to terminate both loops.
    private var isRunning = false

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        os_log(.info, log: log, "Chimera startTunnel called")

        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = tunnelProtocol.providerConfiguration else {
            completionHandler(Self.makeError("providerConfiguration 不存在"))
            return
        }

        let serverAddr = (providerConfiguration["serverAddr"] as? String)
            ?? tunnelProtocol.serverAddress
            ?? ""
        let seedHex = providerConfiguration["seedHex"] as? String ?? ""
        let pskHex = providerConfiguration["pskHex"] as? String ?? ""
        let tunIP = providerConfiguration["tunIP"] as? String ?? "10.99.0.2"

        let generation: Int64
        if let value = providerConfiguration["generation"] as? Int64 {
            generation = value
        } else if let value = providerConfiguration["generation"] as? NSNumber {
            generation = value.int64Value
        } else if let value = providerConfiguration["generation"] as? Int {
            generation = Int64(value)
        } else if let value = providerConfiguration["generation"] as? String {
            generation = Int64(value) ?? 0
        } else {
            generation = 0
        }

        guard !seedHex.isEmpty else {
            completionHandler(Self.makeError("providerConfiguration 中缺少 seedHex"))
            return
        }
        guard !serverAddr.isEmpty else {
            completionHandler(Self.makeError("providerConfiguration 中缺少 serverAddr"))
            return
        }

        do {
            handle = try GoBind.shared.start(
                seedHex: seedHex,
                generation: generation,
                pskHex: pskHex,
                serverAddr: serverAddr
            )
            os_log(.info, log: log, "Go core started with handle %lld", handle)

            let assignedIP = try? GoBind.shared.assignedIP(handle)
            let localIP = assignedIP ?? tunIP
            os_log(.info, log: log, "local TUN address %{public}@ (assigned=%{public}@)", localIP, assignedIP ?? "manual")
        } catch {
            os_log(.error, log: log, "GoBind.start failed: %{public}@", error.localizedDescription)
            completionHandler(error)
            return
        }

        applyNetworkSettings(localIP: localIP) { [weak self] error in
            guard let self = self else {
                completionHandler(error)
                return
            }
            if let error {
                os_log(.error, log: self.log, "setTunnelNetworkSettings failed: %{public}@", error.localizedDescription)
                try? GoBind.shared.stop(self.handle)
                self.handle = -1
                completionHandler(error)
                return
            }

            // Important: signal success only after the virtual interface is
            // fully configured. The system may otherwise treat the tunnel as
            // up before routes/DNS/MTU are applied.
            self.isRunning = true
            completionHandler(nil)

            self.startReaderLoop()
            self.startWriterLoop()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log(.info, log: log, "Chimera stopTunnel called with reason %{public}ld", reason.rawValue)
        isRunning = false

        let currentHandle = handle
        handle = -1
        if currentHandle != -1 {
            do {
                try GoBind.shared.stop(currentHandle)
                os_log(.info, log: log, "Go core stopped for handle %lld", currentHandle)
            } catch {
                os_log(.error, log: log, "GoBind.stop failed: %{public}@", error.localizedDescription)
            }
        }

        completionHandler()
    }

    // MARK: - Virtual interface

    private func applyNetworkSettings(localIP: String, completion: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.99.0.1")

        let ipv4Settings = NEIPv4Settings(addresses: [localIP], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.defaultRoute()]
        settings.ipv4Settings = ipv4Settings

        let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings

        settings.mtu = NSNumber(value: 1400)

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    // MARK: - Data path loops

    /// System-to-Go direction: read IP packets from the packet flow and send
    /// them into the Go core.
    private func startReaderLoop() {
        guard isRunning else { return }

        packetFlow.readPacketObjects { [weak self] packets in
            guard let self = self else { return }
            guard self.isRunning else { return }

            for packet in packets {
                do {
                    try GoBind.shared.send(self.handle, packet: packet.data)
                } catch {
                    os_log(.error, log: self.log, "GoBind.send failed: %{public}@", error.localizedDescription)
                }
            }

            self.startReaderLoop()
        }
    }

    /// Go-to-system direction: wait for IP packets produced by the Go core and
    /// write them back to the packet flow.
    private func startWriterLoop() {
        writerQueue.async { [weak self] in
            guard let self = self else { return }

            while self.isRunning {
                do {
                    let data = try GoBind.shared.receive(self.handle)
                    guard self.isRunning else { break }
                    if data.isEmpty { continue }

                    self.packetFlow.writePackets([data]) { error in
                        if let error {
                            os_log(.error, log: self.log, "writePackets failed: %{public}@", error.localizedDescription)
                        }
                    }
                } catch {
                    if self.isRunning {
                        os_log(.error, log: self.log, "GoBind.receive failed: %{public}@", error.localizedDescription)
                        // Brief pause to avoid a busy-loop while the Go core
                        // is unavailable or in a transient error state.
                        Thread.sleep(forTimeInterval: 0.05)
                    }
                }
            }

            os_log(.info, log: self.log, "Writer loop exited")
        }
    }

    // MARK: - Helpers

    private static func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.chimera.vpn.tunnel",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
