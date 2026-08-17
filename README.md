# CHIMERA PGC — 协议基因编译器（PoC）

CHIMERA 方案的第一步：**不模仿任何已知协议，而是从一颗 256-bit 种子生成一个全新的、结构合理的、可执行的协议物种。**

思路来源：USENIX Security 2025 的 [UPGen](https://www.usenix.org/biblio/fake-title-653)（Unidentified Protocol Generation）。UPGen 的核心观点是：与其伪装成 TLS/QUIC 留下模仿破绽，不如生成“看起来像某种合法加密协议、但谁也没见过”的新协议；审查者若按类别封杀，会误伤加密货币钱包、IoT、游戏、企业内部协议等大量合法流量。

本仓库是这条路线的可运行原型，当前已扩展为跨平台 monorepo。

**接手开发请看文档**：
[交接说明](docs/HANDOFF.md) · [架构](docs/ARCHITECTURE.md) · [协议](docs/PROTOCOL.md) · [构建](docs/BUILD.md) · [部署](docs/DEPLOY.md) · [路线图](docs/ROADMAP.md) · [安全边界](docs/SECURITY.md)



- **Linux 服务端**：`cmd/chimerad`（TUN + UDP 生成协议；`-no-tun` 仅自测回显）
- **Linux 命令行客户端**：`cmd/chimerac`（`-check` 探测 / TUN VPN + 可选默认路由接管）
- **Windows 图形客户端**：`apps/windows`（Wails + Wintun 数据面 + 默认路由接管）
- **Android 客户端**：`apps/android`（Kotlin VpnService + gomobile AAR）
- **iOS 客户端**：`apps/ios`（Swift NEPacketTunnelProvider + gomobile XCFramework）
- **共享内核**：`core/`（所有平台调用同一个 Go 核心）、`bind/`（gomobile 入口）
- **协议编译器**：`internal/{drbg,genome,compiler}`、UDP 传输 `internal/tunnel`

---

## 目前实现了什么

输入 `(seed, generation)`，确定性产出：

1. **握手模式**：6 种（`c_s`、`c_s_c`、`c_s_c_s`、`c_c_s`、`s_c`、`s_c_s`）
2. **每个消息的字段布局**：
   - 明文字段池：`version / type / nonce / reserved`
   - 长度字段：宽度（u8/u16/u24/u32）、大小端、语义（密文长/记录总长）、是否单独分段
   - 加密字段池：`key_material / certificate / extra / pad_length`
   - 字段顺序、固定/前缀编码方式全部随机采样
3. **padding 策略**：`none / uniform / burst`
4. **密码套件**：AES-128/192/256-GCM（Go 标准库）
5. **可执行编解码器**：
   - 按基因组把字段序列化到线上字节
   - AEAD 加密、序列号防重放、篡改检测
   - `LengthAlone` 时把长度字段拆成独立传输分段
   - 流式 `ReadFrame`，支持任意长度字段位置和两种长度语义
6. **可执行握手状态机**：
   - PSK 派生 bootstrap 密钥
   - 双方交换 X25519 临时密钥
   - 用 ECDH + PSK + 握手转录派生前向保密会话密钥
7. **自动化验证**：120 个随机种子端到端握手、全部消息往返、篡改拒绝、流式分帧、模式多样性。

```text
seed ──▶ HMAC-DRBG ──▶ 协议基因组 JSON
                          │
                          ▼
                  Compile(genome, PSK)
                          │
              ┌───────────┴───────────┐
              │ handshake codec table │
              │ X25519 state machine  │
              │ app-record codecs     │
              └───────────┬───────────┘
                          ▼
                  可运行的端到端协议
```

---

## 运行

```bash
cd /home/joy/chimera
go test ./...
go build ./...
bash scripts/selftest.sh          # 不用 root；握手 + 地址分配 + 数据面回显

# 固定种子（32 字节 = 64 个 hex 字符）
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f

# 协议变异：同一个种子、不同 generation，得到完全不同的协议
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -gen 1

# 输出完整基因组 JSON（可用于部署或分析）
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f \
  -json /tmp/chimera-genome.json
```

示例输出：

```text
protocol fingerprint: 329f3b93f59e27ab...
est. design entropy : 119.3 bits
handshake pattern   : c_s

  M0_client  plain=nonce(fixed_bytes) reserved[00] length(u24,big,ciphertext)
             enc=extra(prefixed_u8) key_material(x963) pad_length(u16)
             payload=true pad=uniform[18,253] cipher=aes-192-gcm
  ...
-- handshake demo --
handshake OK over generated pattern "c_s"
app record c2s  : "hello chimera, this is an app record" (round trip OK)
app record s2c  : "payload from the other direction" (round trip OK)
```

---

## 关键设计决策

| 决策 | 原因 |
|---|---|
| 协议规格由种子确定 | 客户端/服务端不需要在线协商“协议长什么样”，无协商字段 = 无指纹可抓 |
| 每服务器一个种子、每代一个变异 | 抓到并识别一个协议，只影响一个服务器的一代协议 |
| 长度字段宽度由最坏情况帧大小反推 | 避免“协议生成了但无法编码合法消息”的无效基因型 |
| 长度字段可位于任意明文位置 | 让前几个字节没有固定结构，提高分类器成本 |
| 非 nonce = (消息索引, 序列号) | 同一 bootstrap 密钥跨多个握手消息复用时不发生 nonce 重用 |
| bootstrap PSK + 临时 X25519 | 握手可先加密，会话密钥仍具前向保密性 |
| 只依赖 Go 标准库 | 密码学实现可审计，构建简单 |

---

## 当前边界（重要）

这**不是**高风险环境下的完整抗审查系统，但数据面与守护进程已按自建 VPN 生产运维收紧：

- 已实现：协议生成、AES-GCM / ChaCha20-Poly1305、UDP 握手（重传/诱饵/静默丢包）、多客户端复用、地址自动分配、Linux TUN 桥接、Linux CLI 客户端（探测 + TUN）、Windows 路由接管、包模式 ACK/SKIP、NAT keepalive、会话配额与限速、包长整形、发送时序抖动、服务端 generation 窗口、chimerad 单会话故障隔离、握手可打印封面（gfw.report FEP Ex2/Ex4）、server-first 认证 knock、握手首包重放表
- 未实现：真机 Android/iOS 验收、车道 B/C（CDN 广播 / 真实应用寄生）、端口跳跃、完整流量变形
- `EstimatedEntropyBits` 是生成器自记账的近似值，不是安全证明

---

## 下一步（按建议顺序）

1. **真机联调**：Android `protect(fd)` + VpnService；iOS excludedRoutes + NEPacketTunnelProvider
2. **车道 B**：密文分片发布到 CDN/直播载体，客户端以拟人行为拉取
3. **对抗评估**：包长分布、时序、分类器误伤率测量（含 gfw.report 启发式在真实网络上的对照）

## 目录

```text
cmd/gencompiler/      CLI：生成、摘要、端到端演示
internal/drbg/        HMAC-DRBG 确定性随机源
internal/genome/      协议基因组类型与生成器
internal/compiler/    编解码、握手状态机、会话
```

---

## 平台状态

| 平台 | 目录 | 状态 |
|---|---|---|
| Linux 服务端 | `cmd/chimerad` | 已实现：多客户端 UDP 握手复用 + TUN 桥接；需 root/CAP_NET_ADMIN + NAT 脚本；` -no-tun` 仅自测 |
| Linux CLI | `cmd/chimerac` | `-check` 探测；TUN + 半默认路由接管（IPv6 `::/1`+`8000::/1` 尽力） |
| Windows GUI | `apps/windows` | Wails GUI + Wintun 包泵 + 默认路由接管 |
| Android | `apps/android` | VpnService + gomobile AAR；`protect(fd)` 防自环 |
| iOS | `apps/ios` | NEPacketTunnelProvider + XCFramework；服务器 `/32` 排除路由 |

## 运行 Linux 服务端

```bash
# 1. 生成本地密钥对
go run ./cmd/chimera-init -dir ./local -server YOUR.PUBLIC.IP:4789

# 2. 构建并安装
CGO_ENABLED=0 go build -o /usr/local/bin/chimerad ./cmd/chimerad
CGO_ENABLED=0 go build -o /usr/local/bin/chimerac ./cmd/chimerac
install -m 644 deploy/chimerad.service /etc/systemd/system/

# 3. 开启转发和 NAT（把 eth0 换成实际出口网卡）
sudo ./scripts/setup-nat.sh eth0

# 4. 启动
sudo systemctl start chimerad
journalctl -u chimerad -f
```

**多客户端与自动分配**：服务端在 `client_cidr`（如 `10.99.0.0/24`）内自动给每个客户端分配唯一 TUN 地址（`.1` 保留给网关，`.2` 起分配，释放后复用）。握手完成后服务器立即下发加密控制包，Android/iOS 先取地址再建虚拟网卡；界面上的“本机 TUN 地址”成为服务端未开启分配时的回退项。

## 移动端构建

GitHub Actions 会上传：

- `Chimera-linux-amd64` — `ubuntu-latest`，`chimerad` + `chimerac` + `chimera-init`
- `ChimeraClient-windows-amd64` — `windows-latest`，Wails GUI + `wintun.dll`
- `ChimeraClient-android-debug` — `ubuntu-latest`，gomobile AAR + `assembleDebug`
- `ChimeraBind-ios-xcframework` — `macos-latest`，gomobile XCFramework（不是已签名 IPA）

```bash
# Android：生成 app/libs/bind.aar（需要 ANDROID_HOME + NDK）
./build/build-mobile-core.sh   # 或 apps/android/build-android-core.sh

# iOS：在 macOS 上生成 ChimeraBind.xcframework
./build/build-mobile-core.sh   # 或 apps/ios/build-ios-core.sh
```

`bind` 包只暴露四个函数：`Start / Stop / Send / Receive`，平台层负责把系统 TUN/NetworkExtension 的数据流与 Go 核心对接。

## 目录

```text
cmd/gencompiler/      协议基因编译器 CLI
cmd/chimerad/         Linux 服务端
cmd/chimerac/         Linux 客户端（-check / TUN）
cmd/chimera-init/     生成匹配的 server.json + client.json
core/                 跨平台客户端/服务端 Go API
bind/                 gomobile 移动端绑定
internal/drbg/        HMAC-DRBG 确定性随机源
internal/genome/      协议基因组类型与生成器
internal/compiler/    编解码、流/包会话、握手状态机
internal/tunnel/      UDP 握手与 packet tunnel
internal/tun/         Linux TUN 抽象
apps/windows/         Windows Wails GUI
apps/android/         Android VpnService 客户端
apps/ios/             iOS NetworkExtension 客户端
configs/ deploy/ build/ scripts/
```
