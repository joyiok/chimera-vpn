import Foundation
import NetworkExtension
import os.log
import Darwin

/// NEPacketTunnelProvider entry point for the ChimeraVPN tunnel target.
///
/// The App saves a `NETunnelProviderProtocol` with these `providerConfiguration` keys:
/// - `serverAddr`: server address in host:port form
/// - `seedHex`: seed for the Chimera protocol
/// - `generation`: generation number for the Chimera protocol
/// - `pskHex`: pre-shared key (64 hex chars; required by the UI)
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.chimera.vpn.tunnel", category: "PacketTunnelProvider")

    /// Serial queue used by the writer loop. `GoBind.receive` blocks until a
    /// packet is available, so it must never run on the main thread.
    private let writerQueue = DispatchQueue(label: "com.chimera.vpn.tunnel.writer", qos: .utility)

    /// Handshake, IdleMillis watchdog, and session swap. Must not be the
    /// writer queue: Receive blocks and would starve the timer.
    private let controlQueue = DispatchQueue(label: "com.chimera.vpn.tunnel.control", qos: .utility)

    private let handleLock = NSLock()

    /// Session handle returned by GoBind.start. -1 means "no session".
    private var handle: Int64 = -1

    /// Set to false by `stopTunnel` to terminate both loops.
    private var isRunning = false

    private var reconnecting = false
    private var session: SessionConfig?
    private var localIP = ""
    private var watchdogTimer: DispatchSourceTimer?

    private struct SessionConfig {
        let serverAddr: String
        let seedHex: String
        let pskHex: String
        let generation: Int64
        let fallbackIP: String
    }

    private static let linkLostMillis: Int64 = 90_000

    override func startTunnel(options: [String: NSObject]? = nil, completionHandler: @escaping (Error?) -> Void) {
        os_log(.info, log: log, "Chimera startTunnel called")
        TunnelShare.resetSession()
        TunnelShare.appendLog("startTunnel")

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

        let cfg = SessionConfig(
            serverAddr: serverAddr,
            seedHex: seedHex,
            pskHex: pskHex,
            generation: generation,
            fallbackIP: tunIP
        )
        session = cfg

        do {
            let newHandle = try GoBind.shared.start(
                seedHex: cfg.seedHex,
                generation: cfg.generation,
                pskHex: cfg.pskHex,
                serverAddr: cfg.serverAddr
            )
            setHandle(newHandle)
            os_log(.info, log: log, "Go core started with handle %lld", newHandle)

            if let assignedIP = try? GoBind.shared.assignedIP(newHandle), !assignedIP.isEmpty {
                localIP = assignedIP
                os_log(.info, log: log, "local TUN address %{public}@ (server assigned)", localIP)
            } else {
                localIP = cfg.fallbackIP
                os_log(.info, log: log, "local TUN address %{public}@ (manual)", localIP)
            }
        } catch {
            os_log(.error, log: log, "GoBind.start failed: %{public}@", error.localizedDescription)
            completionHandler(error)
            return
        }

        applyNetworkSettings(localIP: localIP, serverAddr: cfg.serverAddr) { [weak self] error in
            guard let self = self else {
                completionHandler(error)
                return
            }
            if let error {
                os_log(.error, log: self.log, "setTunnelNetworkSettings failed: %{public}@", error.localizedDescription)
                let h = self.currentHandle()
                try? GoBind.shared.stop(h)
                self.setHandle(-1)
                completionHandler(error)
                return
            }

            // Important: signal success only after the virtual interface is
            // fully configured. The system may otherwise treat the tunnel as
            // up before routes/DNS/MTU are applied.
            self.isRunning = true
            completionHandler(nil)
            TunnelShare.appendLog("connected localIP=\(self.localIP)")

            self.startReaderLoop()
            self.startWriterLoop()
            self.startWatchdog()
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log(.info, log: log, "Chimera stopTunnel called with reason %{public}ld", reason.rawValue)
        TunnelShare.appendLog("stopTunnel reason=\(reason.rawValue)")
        isRunning = false
        stopWatchdog()

        let h = currentHandle()
        setHandle(-1)
        if h != -1 {
            do {
                try GoBind.shared.stop(h)
                os_log(.info, log: log, "Go core stopped for handle %lld", h)
            } catch {
                os_log(.error, log: log, "GoBind.stop failed: %{public}@", error.localizedDescription)
            }
        }

        completionHandler()
    }

    // MARK: - Virtual interface

    private func applyNetworkSettings(localIP: String, serverAddr: String, completion: @escaping (Error?) -> Void) {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.99.0.1")

        let ipv4Settings = NEIPv4Settings(addresses: [localIP], subnetMasks: ["255.255.255.0"])
        ipv4Settings.includedRoutes = [
            NEIPv4Route(destinationAddress: "0.0.0.0", subnetMask: "0.0.0.0")
        ]
        if let host = Self.hostOf(serverAddr), Self.isIPv4(host) {
            ipv4Settings.excludedRoutes = [
                NEIPv4Route(destinationAddress: host, subnetMask: "255.255.255.255")
            ]
        }
        settings.ipv4Settings = ipv4Settings

        let ipv6Settings = NEIPv6Settings(addresses: ["fd99::2"], networkPrefixLengths: [NSNumber(value: 64)])
        ipv6Settings.includedRoutes = [NEIPv6Route.default()]
        settings.ipv6Settings = ipv6Settings

        let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        dnsSettings.matchDomains = [""]
        settings.dnsSettings = dnsSettings

        settings.mtu = NSNumber(value: 1400)

        setTunnelNetworkSettings(settings, completionHandler: completion)
    }

    // MARK: - Reconnect

    private func startWatchdog() {
        stopWatchdog()
        let timer = DispatchSource.makeTimerSource(queue: controlQueue)
        timer.schedule(deadline: .now() + 5, repeating: 5)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            guard self.isRunning else { return }
            let h = self.currentHandle()
            guard h != -1 else { return }
            let idle = (try? GoBind.shared.idleMillis(h)) ?? 0
            if idle >= Self.linkLostMillis {
                self.reconnectGo(reason: "inbound silence \(idle)ms")
            }
        }
        timer.resume()
        watchdogTimer = timer
    }

    private func stopWatchdog() {
        watchdogTimer?.cancel()
        watchdogTimer = nil
    }

    private func reconnectGo(reason: String) {
        controlQueue.async { [weak self] in
            self?.reconnectLocked(reason: reason)
        }
    }

    private func reconnectLocked(reason: String) {
        guard isRunning, !reconnecting, let cfg = session else { return }
        reconnecting = true
        defer { reconnecting = false }

        os_log(.info, log: log, "reconnecting: %{public}@", reason)
        TunnelShare.appendLog("reconnecting: \(reason)")

        let newHandle: Int64
        do {
            newHandle = try GoBind.shared.start(
                seedHex: cfg.seedHex,
                generation: cfg.generation,
                pskHex: cfg.pskHex,
                serverAddr: cfg.serverAddr
            )
        } catch {
            os_log(.error, log: log, "reconnect Start failed: %{public}@", error.localizedDescription)
            return
        }

        let newIP: String
        if let assigned = try? GoBind.shared.assignedIP(newHandle), !assigned.isEmpty {
            newIP = assigned
        } else {
            newIP = cfg.fallbackIP
        }

        if newIP != localIP {
            let sem = DispatchSemaphore(value: 0)
            var applyErr: Error?
            // Completion may run on the caller queue; never wait on that
            // same queue or setTunnelNetworkSettings can deadlock.
            DispatchQueue.global(qos: .userInitiated).async {
                self.applyNetworkSettings(localIP: newIP, serverAddr: cfg.serverAddr) { err in
                    applyErr = err
                    sem.signal()
                }
            }
            sem.wait()
            if let applyErr {
                os_log(.error, log: log, "reconnect settings failed: %{public}@", applyErr.localizedDescription)
                try? GoBind.shared.stop(newHandle)
                return
            }
            localIP = newIP
            os_log(.info, log: log, "TUN address now %{public}@", newIP)
        }

        let old = currentHandle()
        setHandle(newHandle)
        if old != -1, old != newHandle {
            try? GoBind.shared.stop(old)
        }
        os_log(.info, log: log, "reconnected handle %lld", newHandle)
    }

    // MARK: - Data path loops

    /// System-to-Go direction: read IP packets from the packet flow and send
    /// them into the Go core.
    private func startReaderLoop() {
        guard isRunning else { return }

        packetFlow.readPacketObjects { [weak self] packets in
            guard let self = self else { return }
            guard self.isRunning else { return }

            let h = self.currentHandle()
            guard h != -1 else {
                self.startReaderLoop()
                return
            }
            for packet in packets {
                do {
                    try GoBind.shared.send(h, packet: packet.data)
                    TunnelShare.addBytes(sent: packet.data.count, recv: 0)
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
                let h = self.currentHandle()
                if h == -1 {
                    Thread.sleep(forTimeInterval: 0.05)
                    continue
                }
                do {
                    let data = try GoBind.shared.receive(h)
                    guard self.isRunning else { break }
                    if data.isEmpty { continue }

                    let version = data[0] >> 4
                    let family: sa_family_t = version == 6
                        ? sa_family_t(AF_INET6)
                        : sa_family_t(AF_INET)
                    self.packetFlow.writePacketObjects([
                        NEPacket(data: data, protocolFamily: family)
                    ])
                    TunnelShare.addBytes(sent: 0, recv: data.count)
                } catch {
                    if self.isRunning {
                        os_log(.error, log: self.log, "GoBind.receive failed: %{public}@", error.localizedDescription)
                        self.reconnectGo(reason: "receive: \(error.localizedDescription)")
                        Thread.sleep(forTimeInterval: 0.2)
                    }
                }
            }

            os_log(.info, log: self.log, "Writer loop exited")
        }
    }

    // MARK: - Helpers

    private func currentHandle() -> Int64 {
        handleLock.lock()
        defer { handleLock.unlock() }
        return handle
    }

    private func setHandle(_ value: Int64) {
        handleLock.lock()
        handle = value
        handleLock.unlock()
    }

    static func hostOf(_ serverAddr: String) -> String? {
        let trimmed = serverAddr.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("[") {
            guard let close = trimmed.firstIndex(of: "]") else { return nil }
            return String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
        }
        if let idx = trimmed.lastIndex(of: ":") {
            let host = String(trimmed[..<idx])
            let port = trimmed[trimmed.index(after: idx)...]
            if !port.isEmpty, port.allSatisfy({ $0.isNumber }) {
                return host
            }
        }
        return trimmed.isEmpty ? nil : trimmed
    }

    static func isIPv4(_ host: String) -> Bool {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return false }
        return parts.allSatisfy { part in
            guard let n = Int(part) else { return false }
            return n >= 0 && n <= 255
        }
    }

    private static func makeError(_ message: String) -> NSError {
        NSError(
            domain: "com.chimera.vpn.tunnel",
            code: 1,
            userInfo: [NSLocalizedDescriptionKey: message]
        )
    }
}
