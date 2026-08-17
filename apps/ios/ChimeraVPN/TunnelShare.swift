import Foundation

/// Shared App Group store so the Network Extension can publish logs and
/// traffic counters to the containing app. If the group is not provisioned,
/// every call is a no-op and the UI shows an empty log.
enum TunnelShare {
    static let suiteName = "group.com.chimera.vpn"
    private static let logsKey = "tunnelLogs"
    private static let sentKey = "bytesSent"
    private static let recvKey = "bytesRecv"

    static var defaults: UserDefaults? {
        UserDefaults(suiteName: suiteName)
    }

    static func appendLog(_ line: String) {
        guard let d = defaults else { return }
        var lines = d.stringArray(forKey: logsKey) ?? []
        let stamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        lines.append("[\(stamp)] \(line)")
        if lines.count > 200 {
            lines = Array(lines.suffix(200))
        }
        d.set(lines, forKey: logsKey)
    }

    static func logs() -> [String] {
        defaults?.stringArray(forKey: logsKey) ?? []
    }

    static func resetSession() {
        guard let d = defaults else { return }
        d.set([] as [String], forKey: logsKey)
        d.set(NSNumber(value: Int64(0)), forKey: sentKey)
        d.set(NSNumber(value: Int64(0)), forKey: recvKey)
    }

    static func addBytes(sent: Int, recv: Int) {
        guard let d = defaults else { return }
        if sent > 0 {
            let cur = (d.object(forKey: sentKey) as? NSNumber)?.int64Value ?? 0
            d.set(NSNumber(value: cur + Int64(sent)), forKey: sentKey)
        }
        if recv > 0 {
            let cur = (d.object(forKey: recvKey) as? NSNumber)?.int64Value ?? 0
            d.set(NSNumber(value: cur + Int64(recv)), forKey: recvKey)
        }
    }

    static func traffic() -> (sent: Int64, recv: Int64) {
        guard let d = defaults else { return (0, 0) }
        let sent = (d.object(forKey: sentKey) as? NSNumber)?.int64Value ?? 0
        let recv = (d.object(forKey: recvKey) as? NSNumber)?.int64Value ?? 0
        return (sent, recv)
    }

    static func formatBytes(_ n: Int64) -> String {
        let v = Double(max(0, n))
        if v < 1024 { return "\(Int(v)) B" }
        if v < 1024 * 1024 { return String(format: "%.1f KB", v / 1024) }
        if v < 1024 * 1024 * 1024 { return String(format: "%.2f MB", v / 1024 / 1024) }
        return String(format: "%.2f GB", v / 1024 / 1024 / 1024)
    }
}
