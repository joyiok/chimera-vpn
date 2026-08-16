# Chimera iOS 客户端

本目录包含 Chimera VPN 的 iOS 原生客户端工程脚手架。App 使用 SwiftUI，通过 NetworkExtension 的 `NEPacketTunnelProvider`（Packet Tunnel Provider）承载隧道，Go 核心由 gomobile 编译为 `ChimeraBind.xcframework` 后供 Swift 调用。

## 环境要求

- macOS（iOS 开发与 gomobile 绑定都需要在 macOS 上进行）
- Xcode 15 或更高版本
- Go 1.24 或更高版本（仓库根目录 `go.mod` 为准）
- gomobile（`golang.org/x/mobile/cmd/gomobile`）
- 一个已配置好 iOS 开发证书与 App Group 的 Apple Developer 账号

## 目录结构

```
apps/ios/
├── README.md
├── build-ios-core.sh
└── ChimeraVPN/
    ├── ChimeraVPN.xcodeproj/
    │   └── project.pbxproj
    ├── ChimeraVPN/
    │   ├── ChimeraVPNApp.swift
    │   ├── Info.plist
    │   └── ChimeraVPN.entitlements
    ├── ChimeraPacketTunnel/
    │   ├── PacketTunnelProvider.swift
    │   ├── Info.plist
    │   └── ChimeraPacketTunnel.entitlements
    └── GoBind.swift
```

## 编译 Go 核心 XCFramework

在仓库根目录执行：

```bash
./apps/ios/build-ios-core.sh
```

脚本等价于执行：

```bash
go install golang.org/x/mobile/cmd/gomobile@latest   # 若 PATH 中没有 gomobile
gomobile init
gomobile bind \
  -target=ios,iossimulator,macos \
  -iosversion=15.0 \
  -o apps/ios/build/ChimeraBind.xcframework \
  chimera/bind
cp -R apps/ios/build/ChimeraBind.xcframework apps/ios/ChimeraVPN/ChimeraBind.xcframework
```

`gomobile bind` 会为仓库根目录下未来合入的 Go 包 `chimera/bind` 生成 XCFramework，其中导出：

- `Start(seedHex string, generation int64, pskHex string, serverAddr string) (int64, error)`
- `Stop(handle int64) error`
- `Send(handle int64, packet []byte) error`
- `Receive(handle int64) ([]byte, error)`

gomobile 会把 Go 包 `bind` 的顶层函数导出为 `Bind` 前缀的 C 函数（`BindStart`、`BindStop`、`BindSend`、`BindReceive`）。`GoBind.swift` 通过 `#if canImport(ChimeraBind)` 封装这些调用；当 XCFramework 尚未生成或未链接时，Swift 会自动使用返回错误的桩实现，工程仍可解析。

## 签名与 entitlements

Packet Tunnel Provider 必须使用真实开发者账号签名，否则系统会拒绝加载 NetworkExtension。需要处理：

1. 在 Xcode 中为两个 target 选择同一个 Team。
2. 在 Apple Developer 后台注册两个 Bundle ID：
   - App：`com.chimera.vpn`
   - Packet Tunnel Provider：`com.chimera.vpn.tunnel`
3. 开启 App Group，并把两个 target 都加入同一个 App Group，例如 `group.com.chimera.vpn`。
4. 打开 App target 的 Personal VPN 能力（对应 `com.apple.developer.networking.vpn.api` 且值为 `allow-vpn`）。
5. 打开 Packet Tunnel target 的 Network Extension 能力（对应 `com.apple.developer.networking.networkextension` 且值包含 `packet-tunnel-provider`）。

仓库中的 `ChimeraVPN.entitlements` 与 `ChimeraPacketTunnel.entitlements` 只是占位文件，里面的 `group.com.chimera.vpn` 与 `packet-tunnel-provider` 需要在 Xcode 中按实际 Team/App Group 确认或替换。真实 entitlements 由 Xcode 签名时写入，不要在没有对应开发者账号能力的情况下直接签名。

## Packet Tunnel Provider 工作方式

`ChimeraPacketTunnel/PacketTunnelProvider.swift` 是 NetworkExtension 入口：

1. 系统拉起 Provider 扩展并调用 `startTunnel(options:completionHandler:)`。
2. Provider 从 `protocolConfiguration.providerConfiguration` 读取 App 写入的 `serverAddr`、`seedHex`、`generation`、`pskHex`。
3. Provider 通过 `GoBind.shared.start(...)` 调用 Go 核心，获得整数句柄 `handle`。
4. Provider 配置虚拟网卡：
   - `tunnelRemoteAddress`：`10.99.0.1`
   - IPv4：优先使用服务器自动分配的地址；服务端未开启 `client_cidr` 时回退到 `tunIP`（默认 `10.99.0.2/24`）
   - 默认路由：`0.0.0.0/0`
   - DNS：`1.1.1.1`、`8.8.8.8`
   - MTU：`1400`
5. 网卡配置完成后，才调用 `startTunnel` 的 `completionHandler(nil)`。不要提前回调，否则系统可能把尚未就绪的隧道标记为可用。
6. 随后启动两个循环：
   - 读循环：`packetFlow.readPacketObjects` 读取系统交给隧道的 IP 包，逐个调用 `GoBind.shared.send(handle, packet.data)` 送入 Go 核心。
   - 写循环：在后台队列调用 `GoBind.shared.receive(handle)` 获取 Go 核心产生的 IP 包，再通过 `packetFlow.writePackets([data])` 写回系统。
7. `stopTunnel(with:completionHandler:)` 调用 `GoBind.shared.stop(handle)`，停止循环后回调 `completionHandler()`。

## APNs-free 保活说明

本工程不依赖 APNs 推送来唤起隧道。iOS 对已建立的 Packet Tunnel Provider 会尽量保持存活，但仍可能因系统资源压力而终止。工程采用以下策略：

- `startTunnel` 只有在虚拟网卡设置完成并成功调用 `setTunnelNetworkSettings` 后才回调 `completionHandler(nil)`，避免系统在配置未完成时认为隧道可用。
- 连接建立后，读写循环持续运行，让系统认为隧道仍有活跃流量。
- 上层可用 `NEVPNManager` 的 on-demand 规则（本脚手架未强制开启）在需要时重新拉起隧道。
- 如未来需要更激进的保活，可在 Go 核心中发送轻量 keepalive 包，而不是依赖 APNs。

## 使用注意

- 模拟器对 NetworkExtension 支持有限，Packet Tunnel Provider 建议在真机上调试。
- 运行前请先把 `ChimeraBind.xcframework` 链接到 ChimeraPacketTunnel target（脚手架通过 `GoBind.swift` 的条件导入兼容未链接状态；真实运行必须链接）。
- 两个 target 的 Bundle ID 必须与签名证书、App Group 配置一致。
