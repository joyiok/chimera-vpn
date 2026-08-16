# 路线图与实现提示

优先级从上到下。每一项都写了建议的切入文件。

## 1. ~~Windows 默认路由接管~~（已完成，待真机验收）

**实现**：`apps/windows/internal/bridge/route.go`（纯逻辑，跨平台可测）+
`route_windows.go`（GetAdaptersAddresses + netsh）。

- `0.0.0.0/1` + `128.0.0.0/1` 经 Chimera 走 `10.99.0.1`（半默认路由，比任何真实默认路由更精确，无需改 metric）
- 服务器 IP `/32` 例外路由走选出的物理网卡（优先含服务器 IP 的同子网卡，否则 metric 最优网关卡）
- 所有路由 `store=active`：崩溃最坏留一条 /32 例外，重启即清，绝不持久劫持
- `Release()` 对称删除；安装失败自动回滚已装路由
- 路由接管失败按**非致命**处理（隧道仍可用，日志提示手工路由）

**待真机验收**：管理员运行客户端后 `route print -4` 显示两条半默认路由 + 服务器例外；
断开后路由恢复；浏览器出口 IP 变为服务器 IP。

## 2. ~~GitHub Actions CI~~（已完成）

`.github/workflows/ci.yml`：根模块 fmt/vet/test-race/build、Windows 子模块双标签
test/vet + amd64 交叉编译、gobind Java 签名冒烟。

## 3. ~~长期丢包恢复（packet ACK）~~（已完成）

**实现**：ACK/SKIP 加密控制载荷（见 PROTOCOL.md 第 5 节）。接收端每 32 帧周期
ACK 连续位置；发送端未确认跨度达窗口 3/4 时发 SKIP 让对端跳过缺口。
`compiler.PacketSession.AdvanceBaseTo` 清窗推进，越权目标被拒绝。两端对称接入
（`PacketTunnel` / `ServerTunnel`），会话状态由 `sessMu` 串行化。
可选后续：选择性重传（当前为跳过语义，依赖上层协议重传）。

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
