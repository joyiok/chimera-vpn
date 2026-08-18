# 路线图与实现提示

优先级从上到下。每一项都写了建议的切入文件。

## 1. ~~Windows 默认路由接管~~（已完成，待真机验收）

Linux CLI（`cmd/chimerac -take-route`）使用同一套半默认路由语义，另加 IPv6 `::/1`+`8000::/1` 尽力堵泄漏；接管成功后尽力改 systemd-resolved。待远程真机验收。

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
test/vet + amd64 交叉编译、**windows-latest 上 Wails GUI（`with_transport`）并上传
`ChimeraClient.exe` + `wintun.dll`**、**ubuntu-latest 上 gomobile + Gradle debug APK**、
gobind Java 签名冒烟。

## 3. ~~长期丢包恢复（packet ACK）~~（已完成）

**实现**：ACK/SKIP 加密控制载荷（见 PROTOCOL.md 第 5 节）。接收端每 32 帧周期
ACK 连续位置；发送端未确认跨度达窗口 3/4 时发 SKIP 让对端跳过缺口。
`compiler.PacketSession.AdvanceBaseTo` 清窗推进，越权目标被拒绝。两端对称接入
（`PacketTunnel` / `ServerTunnel`），会话状态由 `sessMu` 串行化。
可选后续：选择性重传（当前为跳过语义，依赖上层协议重传）。

## 4. Android 真机联调（代码已接 protect，待真机验收）

**Android**：
1. `apps/android/build-android-core.sh` 生成 AAR。
2. Android Studio 打开工程，连真机。
3. 验证 `GoBind.start` -> `socketFD` + `VpnService.protect` -> `assignedIP` -> TUN。
4. 入站静默 90s 或 Receive 失败会重连 Go 核心（新会话先 `protect`，尽量不拆 TUN）。
5. 已知需检查：前台服务类型在 Android 14+ 的厂商适配；IPv6 `::/0` 与 DNS 是否真正生效。

## 5. ~~探测诱饵（anti-probe decoy）~~（已完成）

**实现**：`internal/tunnel/decoy.go` + `ServerMux.WithDecoy`。非法首包（client-first
模式 RecvStep 失败）用 `generation XOR 0xC0DEC0DEC0DEC0DE` 生成的第二种协议回一帧；
源地址 1s 间隙 + 全局 32 帧/秒 + 体积 ≤ min(1200, 3×探测包) 防放大。
`disable_decoy` 可关。server-first 需要 PSK-MAC knock，随机探针不再拿到真实首帧。

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

## 8. 安全加固（部分完成）

- ~~ChaCha20-Poly1305 接入 `internal/compiler`~~ ✅（`GenerateWithCipher` 强制覆盖 +
  `core.Config.Cipher`；两端一致才可握手）
- ~~握手重放窗口~~ ✅（流模式 64 序号位图，跳跃判死整段；见 PROTOCOL.md 第 4 节）
- ~~服务端每会话限速~~ ✅（`WithRateLimit` 令牌桶；`max_sessions` 默认 256）
- ~~NAT keepalive + 空闲会话回收~~ ✅（生产存活硬需求：`ControlKeepalive` 0x04、
  `WithIdleTimeout`；客户端 `SetKeepalive`）
- ~~包长整形~~ ✅（`compiler.DefaultShapeBuckets` 128/512/1024/1452；无 pad_length
  的基因型跳过；`disable_shape` 可关）
- ~~时序抖动~~ ✅（截断指数 IAT，上限 `jitter_ms` 默认 20ms；对齐 obfs4/CCS 2015，
  不用均匀间隔）
- ~~密钥轮换协议~~ ✅（服务端 `GenerationWindow` 并行接受 gen…gen+N；客户端超时探测。
  server-first knock 仍绑定基代，见 PROTOCOL.md）
- ~~GFW 全加密启发式（gfw.report / Wu 2023）~~ ✅（握手数据报随机可打印封面 Ex2/Ex4；
  不模仿 TLS/HTTP）
- ~~主动探测确认预言机（IMC 2020）~~ ✅（认证 knock + 已认证首包重放表，默认可落盘）

## 9. 多机/分布式部署

- 配置分发（seed/psk/generation 的安全下发）。
- 用户管理、多服务器调度。
- 在 Windows 路由完成后，做真实跨平台吞吐测试（目标先定 100 Mbps 起步）。
