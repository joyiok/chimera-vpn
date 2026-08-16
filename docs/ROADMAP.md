# 路线图与实现提示

优先级从上到下。每一项都写了建议的切入文件。

## 1. Windows 默认路由接管（当前最优先）

**现状**：Wintun 已能收发包，但系统流量是否走 Chimera0 取决于用户手工路由。

**要做**：
- `0.0.0.0/0`（或 0/1 + 128/1）经 Chimera0，下一跳 `10.99.0.1`
- **服务器 IP/32 例外路由**走原物理网关，否则隧道自环
- 关闭时恢复原路由

**切入文件**：`apps/windows/internal/bridge/bridge_windows.go`

**实现提示**：
- 用 `golang.org/x/sys/windows.GetAdaptersAddresses`（`GAA_FLAG_INCLUDE_GATEWAYS`）
  找到物理网卡 `FriendlyName`、`FirstGatewayAddress`。
- 用 `netsh interface ipv4 add route prefix=0.0.0.0/0 interface="Chimera" nexthop=10.99.0.1 metric=5 store=active`。
- 服务器例外：`prefix=<serverIP>/32 interface="<物理网卡>" nexthop=<物理网关> metric=1 store=active`。
- `Bridge.Close()` 对称执行 `netsh ... delete route`。
- 服务器 IP 从 `core.Config.ServerAddr` 解析（`net.LookupHost`）。
- 更稳的长期方案：升级 `golang.org/x/sys` 到含 IP Helper 路由结构的新版本，或引入
  `golang.zx2c4.com/wireguard/windows/tunnel/winipcfg`。

**验收**：管理员运行客户端后，`route print -4` 显示 Chimera0 默认路由 + 服务器例外；
断开后路由恢复；浏览器出口 IP 变为服务器 IP。

## 2. GitHub Actions CI

**要做**：
- 根模块：`go test -race ./...`、`go vet ./...`、gofmt 检查。
- Windows 子模块：`go test ./...` 与 `go test -tags with_transport ./...`、
  `GOOS=windows go build -tags with_transport ./...`。
- 可选：`gobind -lang=java` 冒烟。

**切入文件**：`.github/workflows/ci.yml`（新建）

## 3. 长期丢包恢复（packet ACK）

**现状**：`PacketMessageCodec` 的 8192 帧重排窗口；某帧永久丢失会卡住 `base`。

**要做**：
- 在数据载荷里加轻量控制类型（如 `0x02=ACK`），周期性 ACK 最大连续序号。
- 发送端在 N 个 RTT 后把未 ACK 的缺口标记为“已放弃”。
- 接收端按 ACK 推进 base，而不是等缺口补上。
- 可选：简单滑动窗口 + 选择性重传。

**切入文件**：`internal/compiler/packet.go`（nonce 窗口）、`internal/tunnel/tunnel.go`、
`internal/tunnel/mux.go`（服务端同逻辑）。

## 4. Android/iOS 真机联调

**Android**：
1. `apps/android/build-android-core.sh` 生成 AAR。
2. Android Studio 打开工程，连真机。
3. 验证 `GoBind.start` -> `assignedIP` -> TUN 建立 -> 双泵。
4. 已知需检查：前台服务类型在 Android 14+ 的厂商适配；DNS 是否真正生效。

**iOS**：
1. macOS 上 `build-ios-core.sh` 生成 XCFramework 并链入两个 target。
2. 配置 App Group + NetworkExtension entitlements。
3. 验证 `PacketTunnelProvider` 中 `GoBind.assignedIP` 阻塞 10s 内返回。

## 5. 探测诱饵（anti-probe decoy）

- 对非法首包，可选地以“另一种良性协议”的响应应答，污染分类器训练样本。
- 服务端按源地址限速，避免被用作反射放大。
- 切入：`internal/tunnel/mux.go` 的 `handleDatagram`。

## 6. 车道 B：CDN/直播广播下行

- 服务端把加密分片编码成 HLS/DASH 分片或对象存储对象，URI 由 seed 派生。
- 客户端以拟人浏览行为拉取，解密后入本地 TUN。
- 参考：CovertCast、OUStralopithecus、Slitheen。
- 切入：新增 `internal/laneb/`，服务端 `cmd/chimerad` 增加 publisher。

## 7. 车道 C：真实应用寄生（Balboa 风格）

- 运行真实 TLS 应用，按预共享流量模型把密文替换为“指向模型位置的指针 + 隐蔽数据”。
- 吞吐预期低（Mbps 级），用于极端环境控制信令。
- 参考：Balboa、Stegozoa。
- 切入：新增 `internal/lanec/`，平台壳集成。

## 8. 安全加固

- ChaCha20-Poly1305 接入 `internal/compiler`。
- 握手重放窗口（每方向记录已见 nonce 位图）。
- 服务端每会话限速与连接配额。
- 包长/时序整形（先做包长分布统计工具）。
- 密钥轮换协议（genome generation 自动切换）。

## 9. 多机/分布式部署

- 配置分发（seed/psk/generation 的安全下发）。
- 用户管理、多服务器调度。
- 在 Windows 路由完成后，做真实跨平台吞吐测试（目标先定 100 Mbps 起步）。
