# 构建与运行

## 通用前置

- Go 1.24+（根模块 `go.mod` 声明 1.24）
- 根目录跑测试：

```bash
cd chimera
gofmt -l .            # 期望无输出（忽略 frontend/node_modules）
go vet ./...
go test -race ./...
go build ./...
bash scripts/selftest.sh   # 不用 root
```

## 协议基因编译器

```bash
go run ./cmd/gencompiler -seed <64 hex chars> [-gen N] [-json out.json]
```

- 不传 `-seed` 会随机生成并打印，务必保存。
- `-json` 导出完整协议规格；同 seed+gen 永远得到相同结果。

## Linux 服务端

```bash
# 构建
CGO_ENABLED=0 go build -o dist/chimerad ./cmd/chimerad
./build/build-linux.sh        # amd64 + arm64

# 配置 /etc/chimera/server.json
{
  "listen": "0.0.0.0:4789",
  "seed_hex": "...",
  "generation": 0,
  "psk_hex": "...",
  "client_cidr": "10.99.0.0/24",
  "cipher": "",
  "keepalive_sec": 25,
  "idle_timeout_sec": 180,
  "rate_limit_kbps": 0,
  "max_sessions": 256,
  "disable_decoy": false,
  "disable_shape": false,
  "jitter_ms": 20,
  "generation_window": 2,
  "tun": {"name":"chimera0","address":"10.99.0.1/24","mtu":1400}
}

# cipher: 空串 = 基因组默认（AES 档抽签）；"chacha20-poly1305" 强制 ChaCha
#         （客户端配置必须一致，否则握手失败）。客户端同样支持 cipher 字段。
# keepalive_sec: 0 = 默认 25s（防 NAT 超时），负数禁用
# idle_timeout_sec: 空闲会话回收阈值，0 = 不回收
# rate_limit_kbps: 每客户端入口限速（KiB/s），0 = 不限速
# max_sessions: 已建立会话上限（默认 256）
# disable_decoy / disable_shape: 关闭探测诱饵 / 包长整形
# jitter_ms: 发送时序抖动上限（省略或 0 = 20ms，负数关闭）
# generation_window: 额外接受 gen..gen+N（省略 = 2，0 = 只接受配置的 generation）
# replay_path: 握手重放表落盘（省略 = /var/lib/chimera/handshake.replay，空串 = 仅内存）
# 校验配置：chimerad -config /etc/chimera/server.json -check-config
# 配置文件权限建议 0600（含 PSK）
# 本机自测（不用 TUN）：chimerad -config … -no-tun ；chimerac -check
# 一页部署：docs/DEPLOY.md

# 运行（需 root 或 CAP_NET_ADMIN）
sudo ./dist/chimerad -config /etc/chimera/server.json

# NAT
sudo ./scripts/setup-nat.sh eth0
```

systemd 单元见 `deploy/chimerad.service`。不要把 `-no-tun` 写进生产单元。

## Linux 客户端

```bash
CGO_ENABLED=0 go build -o dist/chimerac ./cmd/chimerac
./dist/chimerac -config client.json -check          # 握手 + ICMP 探测，不用 TUN
sudo ./dist/chimerac -config client.json -take-route
```

`-check` 对 `-no-tun` 服务端得到 `probe=echo`，对真实 TUN 服务端得到 `probe=icmp-reply`。
`-take-route` 安装 `0.0.0.0/1` + `128.0.0.0/1` 经 TUN，服务器 IPv4 `/32` 走 `ip route get` 选出的物理网卡；回环地址拒绝接管。IPv6 半默认路由尽力安装，防 IPv6 泄漏。接管成功后尽力执行 `resolvectl dns <tun> 1.1.1.1 8.8.8.8` 与 `domain ~.`，退出时 `resolvectl revert`。入站静默超过 `-lost-after`（默认 90s）自动重握手；自己发出的 keepalive 不再被当成对端还活着。

配对配置：`go run ./cmd/chimera-init -dir ./local -server host:4789`。

## Windows 客户端

前置：Windows 10/11、Go 1.24+、Node 20+、Wails v2.10.x。

```bat
cd apps\windows
npm install
wails build -tags with_transport
```

或开发模式：`wails dev -tags with_transport`。

构建/运行前：
1. 把 `wintun.dll` 放到 `ChimeraClient.exe` 同目录。
2. 以管理员运行（netsh 配置需要）。
3. 服务端要开 `client_cidr`；否则客户端回退 `10.99.0.2`。

连接成功后自动接管默认路由：`0.0.0.0/1` + `128.0.0.0/1` 经 Wintun 网卡，
服务器 IP 以 `/32` 例外路由保持走物理网卡（防隧道自环）。断开时自动还原；
所有路由 `store=active`，崩溃残留重启即清。路由接管失败不影响隧道本身，
只记日志（可手工 `route add`）。验收：`route print -4` 应看到两条半默认路由。

Linux 交叉验证命令（本项目实际执行过）：

```bash
cd apps/windows
go test ./...
go test -tags with_transport ./...
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -tags with_transport ./...
```

真正的 GUI 可执行文件必须在 Windows 上用 Wails + CGO 构建。GitHub Actions
job `windows-wails`（`windows-latest`）会执行 `wails build -tags with_transport`，
附带官方签名的 `wintun.dll`，并把 `ChimeraClient-windows-amd64` 作为
workflow artifact 上传。PR / `main` 推送 / 手动 `workflow_dispatch` 都会跑。
产物未代码签名，SmartScreen 可能提示，见 `apps/windows/build/README.md`。

## Android

```bash
cd apps/android
./build-android-core.sh      # 需要 ANDROID_HOME + NDK，生成 app/libs/bind.aar
# 然后用 Android Studio 打开 apps/android，或：
#   gradle assembleDebug     # Gradle 8.7+ / JDK 17 / compileSdk 35
```

未生成 AAR 时工程也能编译，连接时给出明确错误。
Go 绑定 API 见 `bind/bind.go`；`gobind -lang=java chimera/bind` 可离线核对签名。
`gomobile bind` 使用 `-androidapi 26`（与 `minSdk` 一致；新 NDK 已不再提供 API 16）。

GitHub Actions job `android-apk`（`ubuntu-latest`）会装 SDK/NDK、
跑 `build-android-core.sh`、再 `gradle assembleDebug`，上传 artifact
`ChimeraClient-android-debug`（`app-debug.apk` + `bind.aar`）。Debug APK 用
Android 默认 debug 密钥，可 sideload，不是 Play 签名包。

## 移动端 Go 绑定签名核对

```bash
go run golang.org/x/mobile/cmd/gobind@latest -lang=java chimera/bind
```

会生成 `Start / AssignedIP / Stop / Send / Receive / SocketFD / IdleMillis / BytesSent / BytesRecv` 的 Java 签名。
Android 必须在 `establish()` 之前对 `SocketFD` 调用 `VpnService.protect`。
`IdleMillis` 是入站静默毫秒数，平台看门狗用来判定掉线重连。
