import Foundation

#if canImport(ChimeraBind)
import ChimeraBind
#endif

/// Errors thrown by the GoBind wrapper when the real gomobile framework is
/// not linked, or when the caller passes invalid arguments.
public enum GoBindError: LocalizedError {
    /// The ChimeraBind XCFramework has not been built or linked yet.
    case frameworkUnavailable
    /// The Go core returned/uses an invalid session handle.
    case invalidHandle
    /// Empty packet data is never valid for the Go core.
    case emptyPacket

    public var errorDescription: String? {
        switch self {
        case .frameworkUnavailable:
            return "ChimeraBind XCFramework 未集成。请先运行 apps/ios/build-ios-core.sh 生成 XCFramework，并在 Xcode 中链接到 ChimeraPacketTunnel target。"
        case .invalidHandle:
            return "Go Bind 句柄无效。"
        case .emptyPacket:
            return "不能发送空数据包。"
        }
    }
}

/// Thin Swift wrapper around the gomobile-generated `ChimeraBind` module.
///
/// The Go package `chimera/bind` is compiled by `gomobile bind` into
/// `ChimeraBind.xcframework`. gomobile exports Go package-level functions as
/// C functions prefixed with the package name (`BindStart`, `BindStop`,
/// `BindSend`, `BindReceive`). This wrapper isolates the Packet Tunnel
/// Provider from the exact generated naming, and provides stub
/// implementations when the XCFramework is not available yet.
///
/// Note: Swift cannot conditionally `import` a module without `#if`, so the
/// real import is guarded by `#if canImport(ChimeraBind)`. Build
/// `ChimeraBind.xcframework` first and link it to the
/// `ChimeraPacketTunnel` target for the real branch to compile and run.
public final class GoBind {

    public static let shared = GoBind()

    private init() {}

    #if canImport(ChimeraBind)

    /// Calls Go core `Start(seedHex, generation, pskHex, serverAddr)`.
    /// - Returns: an opaque session handle (int64) for subsequent calls.
    public func start(seedHex: String, generation: Int64, pskHex: String, serverAddr: String) throws -> Int64 {
        try BindStart(seedHex, generation, pskHex, serverAddr)
    }

    /// Calls Go core `AssignedIP(handle)`.
    public func assignedIP(_ handle: Int64) throws -> String {
        try BindAssignedIP(handle)
    }

    /// Calls Go core `Stop(handle)`.
    public func stop(_ handle: Int64) throws {
        try BindStop(handle)
    }

    /// Calls Go core `Send(handle, packet)`.
    public func send(_ handle: Int64, packet: Data) throws {
        guard !packet.isEmpty else {
            throw GoBindError.emptyPacket
        }
        try BindSend(handle, packet)
    }

    /// Calls Go core `Receive(handle)` and returns an IP packet.
    public func receive(_ handle: Int64) throws -> Data {
        try BindReceive(handle)
    }

    /// Calls Go core `IdleMillis(handle)` (inbound silence). Rebuild
    /// ChimeraBind.xcframework after adding this export.
    public func idleMillis(_ handle: Int64) throws -> Int64 {
        try BindIdleMillis(handle)
    }

    #else

    public func start(seedHex: String, generation: Int64, pskHex: String, serverAddr: String) throws -> Int64 {
        throw GoBindError.frameworkUnavailable
    }

    public func assignedIP(_ handle: Int64) throws -> String {
        throw GoBindError.frameworkUnavailable
    }

    public func stop(_ handle: Int64) throws {
        throw GoBindError.frameworkUnavailable
    }

    public func send(_ handle: Int64, packet: Data) throws {
        guard !packet.isEmpty else {
            throw GoBindError.emptyPacket
        }
        throw GoBindError.frameworkUnavailable
    }

    public func receive(_ handle: Int64) throws -> Data {
        throw GoBindError.frameworkUnavailable
    }

    public func idleMillis(_ handle: Int64) throws -> Int64 {
        throw GoBindError.frameworkUnavailable
    }

    #endif
}
