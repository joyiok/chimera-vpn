# 架构文档

## 代码地图

```text
chimera/                     Go module `chimera`，go 1.24
├── cmd/gencompiler/         协议基因编译器 CLI（可独立演示）
├── cmd/chimerad/            Linux 服务端（`-no-tun` 自测回显）
├── cmd/chimerac/            Linux 客户端（`-check` / TUN）
├── cmd/chimera-init/        生成匹配的 server.json + client.json
├── core/                    跨平台 Client/Server API + IPv4 地址池
├── bind/                    gomobile 绑定：Start/AssignedIP/Stop/Send/Receive
├── internal/
│   ├── drbg/                HMAC-DRBG-SHA256 确定性随机源
│   ├── genome/              协议基因组类型与生成器
│   ├── compiler/            编解码器、握手状态机、Session/PacketSession
│   ├── tunnel/              UDP 握手、PacketTunnel、ServerMux 多路复用
│   ├── tun/                 Linux TUN 设备封装
│   └── netpkt/              IPv4/ICMP 探测包与路由辅助
├── apps/windows/            Wails v2 子模块（module chimera/windows-client）
│   ├── app.go               GUI 后端：Start/Stop/Status/Config
│   ├── core_bridge.go       默认 stub（build tag !with_transport）
│   ├── core_bridge_transport.go  真实 core 调用（build tag with_transport）
│   └── internal/bridge/     Wintun 数据面（Windows）/ stub（其他平台）
├── apps/android/            Android Studio 工程（Kotlin + VpnService）
├── apps/ios/                Xcode 工程（Swift + NetworkExtension）
├── configs/ deploy/ build/ scripts/
└── docs/
```

## 依赖方向

```text
apps/windows ──replace──▶ 根模块 chimera/core
apps/android/iOS ──gomobile──▶ chimera/bind ──▶ chimera/core
cmd/chimerad + cmd/chimerac ──▶ chimera/core ──▶ internal/tunnel ──▶ internal/compiler ──▶ internal/genome
```

规则：
- `internal/genome` 只依赖 `internal/drbg`，不依赖网络。
- `internal/compiler` 不知道 UDP/TCP，只处理“一帧字节”。
- `internal/tunnel` 只处理握手与包转发，不知道 IP 包内容。
- 平台壳（VpnService / NEPacketTunnelProvider / Wintun）只负责系统 TUN 与 `Send/Receive` 字节搬运。

## 数据流（VPN 模式）

```text
手机/PC 应用 ──原始IP包──▶ TUN 设备
                            │
                            ▼
                 bind.Send(handle, pkt) / core.Client.SendPacket
                            │
                            ▼
              PacketSession.EncodePacket（生成协议帧，AEAD）
                            │
                            ▼
                     UDP datagram ──────▶ Linux 服务端
                                            │ ServerMux 按源地址解复用
                                            │ PacketSession.DecodePacket
                                            ▼
                                     TUN 写入 chimera0
                                            ▼
                                     Linux 内核路由/NAT ──▶ 互联网
```

回程按目的 IP 反向：`chimera0 读包 → 解析 dst IP → 查 clientRoute → 对应 Conn.SendPacket`。

## 核心 API 契约（平台开发者必读）

`core` 包：

```go
type Config struct {
    SeedHex            string
    Generation         uint64
    GenerationWindow   uint64        // 服务端并行接受；客户端超时探测
    PSKHex             string
    ServerAddr         string
    ClientCIDR         string
    JitterMax          time.Duration // 0 = 关闭；生产默认 20ms
}

client, _ := core.NewClient(cfg)
client.Start()                       // 完成 UDP 握手
ip, _ := client.AssignedIP(ctx)      // 等服务器分配 TUN 地址（控制包）
client.SendPacket(ipPacket)
pkt, _ := client.ReceivePacket()
client.Close()

server, _ := core.NewServer(cfg)
server.Start()                       // 绑定并后台 accept
conn, _ := server.Accept(ctx)        // 每个握手完成的客户端
conn.AssignedIP()
conn.SendPacket(pkt)
pkt, _ := conn.ReceivePacket()
conn.Close()
```

`bind` 包（gomobile 导出）：

```go
func Start(seedHex string, generation int64, pskHex string, serverAddr string) (int64, error)
func AssignedIP(handle int64) (string, error)   // 阻塞最多 10s
func Stop(handle int64) error
func Send(handle int64, packet []byte) error
func Receive(handle int64) ([]byte, error)      // 阻塞
```

平台时序（Android/iOS 已按此实现）：

```text
Start() -> AssignedIP() -> 用分配地址创建 TUN -> 启动两条泵
泵1: TUN.read -> Send(handle, pkt)
泵2: Receive(handle) -> TUN.write(pkt)
```

## 会话状态机

- 握手：`compiler.Handshake`，模式由基因组决定，UDP 侧由 `tunnel.runHandshake`/`ServerMux` 驱动。
- 流模式：`compiler.Session`，要求有序可靠流，`ReadFrame` 用长度字段分帧。
- 包模式：`compiler.PacketSession`，允许乱序（8192 帧窗口），用于 TUN IP 包。
- 服务端多路复用：`tunnel.ServerMux` 单 socket 同时管理 pending 握手表 + established 会话表。

## 并发与锁

- `ServerMux.pending`/`established` 受 `mux.mu` 保护。
- 每个 `pendingHandshake` 有独立 `mu`；reader 和重传 timer 不同时持有全局锁。
- `ServerTunnel.recv` 每客户端队列深度 128，满则丢包（避免阻塞共享读循环）。
- `core.Client` 的 `mu` 保护启动/关闭状态；`ReceivePacket` 取指针后解锁再阻塞。
- `PacketTunnel.data`（256）缓存在等控制包期间提前到达的数据包。
