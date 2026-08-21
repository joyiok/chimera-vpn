# CHIMERA Windows 客户端（chimera-windows）

基于 **Wails v2** 的 Windows 图形客户端：Go 后端负责协议控制与配置持久化，
HTML/JS/CSS 前端运行在 WebView2 中，前端通过 Wails 绑定调用后端方法。
关窗口会进系统托盘（右键连接/断开/退出）；界面含流量火花图和 host:port 入口列表。

> 目录约定：本目录只包含 Windows 客户端。仓库根模块路径为 `chimera`，
> 核心传输层位于 `../../core`（`chimera/core`）。本应用默认以 stub 方式编译；
> 核心已合并时，使用 `with_transport` 构建标签即可切换到真实传输层。

---

## 1. 目录结构

```text
apps/windows/
├── main.go                      # Wails v2 入口，嵌入 frontend/dist
├── app.go                       # ChimeraApp 后端：Start/Stop/Status/Config 等
├── core_bridge.go               # 默认构建（!with_transport）：传输层 stub
├── core_bridge_transport.go     # with_transport 构建：调用 chimera/core
├── go.mod / go.sum              # module chimera/windows-client，含 wails 与 chimera 依赖
├── wails.json                   # Wails 项目配置
├── frontend/                    # Vite + 原生 JS 前端（暗色中文 UI）
│   ├── index.html
│   ├── package.json
│   ├── vite.config.js
│   ├── src/main.js
│   ├── src/style.css
│   └── dist/index.html          # 占位产物，便于 go:embed 在未构建前端时可用
└── build/
    ├── build.bat                # 生产构建脚本
    ├── dev.bat                  # 开发模式脚本
    ├── appicon.png              # AI 生成的应用图标源图（Wails 构建时读取）
    ├── windows/icon.ico         # 16–256px 多尺寸图标，嵌入 exe 与托盘
    └── README.md                # Windows Defender 与代码签名说明
```

---

## 2. 环境准备（Windows 10/11）

| 依赖 | 版本要求 | 说明 |
| --- | --- | --- |
| Go | 1.24+ | 与仓库根 `go.mod` 保持一致 |
| Node.js | 20+ | 含 npm |
| Wails CLI | v2 | 建议 v2.10.2 |
| WebView2 Runtime | 最新 | Windows 10/11 通常已内置 |

安装 Wails CLI：

```bat
go install github.com/wailsapp/wails/v2/cmd/wails@v2.10.2
```

确认安装：

```bat
wails version
wails doctor
```

---

## 3. 构建与运行

```bat
cd /d 仓库根目录\apps\windows
```

安装前端依赖：

```bat
npm install
```

### 3.1 默认构建（stub：界面可运行，传输层未编译）

```bat
wails build
```

产物：`build\bin\ChimeraClient.exe`。

此时点击“连接”会收到：

```text
transport not compiled: rebuild with -tags with_transport
```

这是预期行为，表示 GUI 与绑定链路已经工作，只是当前未启用真实传输层。

> 如果 `go mod tidy` 报错找不到 `chimera/core`（即核心尚未合并的提交），
> 请使用跳过 tidy 的构建方式，只编译 stub 界面：
> ```bat
> wails build -m
> ```

### 3.2 开发模式（热重载前端）

```bat
wails dev
```

核心未合并时同理：

```bat
wails dev -m
```

### 3.3 真实传输层构建（核心已合并）

当仓库根目录已提供 `chimera/core` 包（`../../core`）后：

```bat
wails build -tags with_transport
```

开发模式：

```bat
wails dev -tags with_transport
```

> `go.mod` 中已经声明了 `require chimera` 和 `replace chimera => ../..`，
> 因此核心合并后可直接使用 `with_transport` 标签；如依赖有变化，可先执行
> `go mod tidy` 再构建。

也可以直接使用脚本（自动检测 `../../core` 是否存在）：

```bat
build\build.bat
build\build.bat with_transport
build\dev.bat
build\dev.bat with_transport
```

### 3.4 CI 构建

本机没有 Windows 时，用 GitHub Actions job `windows-wails`：

- runner：`windows-latest`（Wails + CGO + WebView2；Linux 交叉编译出不了 GUI）
- 命令：`wails build -tags with_transport`
- 产物 artifact：`ChimeraClient-windows-amd64`（`ChimeraClient.exe` + 官方签名 `wintun.dll`）

在 Actions 打开对应 run 下载 artifact，或手动 `workflow_dispatch`。
未签名 exe 可能触发 SmartScreen，见 `build/README.md`。

---

## 4. 架构说明

### 4.1 Wails v2 架构

```text
┌─────────────────────────────────────────────┐
│              ChimeraClient.exe              │
│  ┌───────────────────────────────────────┐  │
│  │              WebView2                  │  │
│  │   HTML/JS/CSS (Vite 构建产物)           │  │
│  │   window.go.main.ChimeraApp.Start(...) │  │
│  └───────────────▲───────────────────────┘  │
│                  │ Wails 绑定               │
│  ┌───────────────┴───────────────────────┐  │
│  │           Go 后端（package main）       │  │
│  │   ChimeraApp / core_bridge / 配置持久化 │  │
│  └───────────────▲───────────────────────┘  │
│                  │ 仅 with_transport 构建时 │
│  ┌───────────────┴───────────────────────┐  │
│  │        chimera/core（仓库根模块）       │  │
│  └───────────────────────────────────────┘  │
└─────────────────────────────────────────────┘
```

### 4.2 前端调用后端

Wails v2 按 **Go 结构体名** 注入绑定。后端是 `type ChimeraApp struct`、
`package main`，所以运行时是 `window.go.main.ChimeraApp`，不是 `.App`。
前端 `getAPI()` 会按 `ChimeraApp` / `App` 查找，避免 v0.1.0 那种界面正常却
提示「Wails 绑定不可用」的情况。

```js
await window.go.main.ChimeraApp.Start(seedHex, generation, pskHex, serverAddr)
await window.go.main.ChimeraApp.Stop()
const status = await window.go.main.ChimeraApp.Status()
const cfg = await window.go.main.ChimeraApp.Config()
const defaultServer = await window.go.main.ChimeraApp.SelectServerDefault()
```

### 4.3 后端方法

| 方法 | 说明 |
| --- | --- |
| `Start(seedHex string, generation uint64, pskHex string, serverAddr string) error` | 兼容旧前端；沿用已保存的 transport/splitTunnel 配置 |
| `StartWithTransport(seedHex, generation, pskHex, serverAddr, transport string) error` | 指定 udp/tcp 传输启动 |
| `StartAdvanced(seedHex, generation, pskHex, serverAddr, transport string, splitTunnel bool) error` | 指定传输 + 是否分流（局域网/私网直连）启动 |
| `StartWithOptions(..., transport string, splitTunnel bool, portHopCount, portHopSpread int) error` | 完整参数：传输 + 分流 + 端口跳跃 |
| `Stop() error` | 优雅停止传输层，应用进程保持存活 |
| `Status() string` | 返回 `disconnected` / `connecting` / `connected` / `error: <detail>` |
| `Config() (map[string]any, error)` | 返回当前保存的 `seedHex/generation/pskHex/serverAddr/transport/splitTunnel` |
| `SelectServerDefault() string` | 返回默认服务器地址常量 `127.0.0.1:4789` |

### 4.4 core_bridge 构建标签

```text
core_bridge.go               //go:build !with_transport   默认 stub
core_bridge_transport.go     //go:build with_transport    真实 chimera/core
```

默认构建不 import `chimera/core`，因此核心未合并时也能编译 GUI。
`with_transport` 构建按计划 API 调用：

```go
core.Config{SeedHex, Generation, PSKHex, ServerAddr}
core.NewClient(cfg) (*core.Client, error)
client.Start() error
client.SendPacket(ipPacket []byte) error
client.ReceivePacket() ([]byte, error)
client.Close() error
```

### 4.5 配置持久化

配置以 JSON 形式保存在可执行文件旁：

```text
<exe所在目录>\chimera-config.json
```

文件内容示例：

```json
{
  "seedHex": "00ff...",
  "generation": 0,
  "pskHex": "11ee...",
  "serverAddr": "127.0.0.1:4789"
}
```

配置中包含 PSK，因此写入时使用 `0600` 权限位（Windows 上按 NTFS 语义处理）。
生产环境建议进一步考虑使用 DPAPI 加密 PSK。

---

## 5. 常见问题

### Q1：`go mod tidy` 报 `does not contain package chimera/core`
说明当前提交尚未合并核心传输层。请使用 `wails build -m` / `wails dev -m`
跳过 tidy 构建 stub 界面；合并核心后再使用标准命令。

### Q2：默认构建连接时报 `transport not compiled`
这是 stub 的预期行为。请在核心合并后使用 `wails build -tags with_transport`。

### Q3：前端提示 `Wails 绑定不可用`
先确认打开的是 `ChimeraClient.exe`（同目录要有 `wintun.dll`），不要用浏览器打开 HTML。
v0.1.0 还会在 **exe 里** 报这句：前端只认 `window.go.main.App`，Wails 实际挂的是
`ChimeraApp`。请用包含该修复的构建。日志里会打印实际注入的 `window.go` 键名。

### Q4：`go:embed` 报 `frontend/dist` 不存在
仓库已包含占位的 `frontend/dist/index.html`。如果 Vite 清理了该目录，
请重新运行 `npm run build` 后再执行 `go build` 或 `wails build`。

### Q5：Windows SmartScreen / Defender 提示
见 `build/README.md`。开发阶段可忽略；发布前必须做代码签名。

### Q6：`wails build -m` 中的 `-m` 是什么？
Wails CLI 的 `-m`/`--skipmodtidy` 选项会跳过编译前的 `go mod tidy`。
当 `chimera/core` 尚未合并导致 tidy 无法解析该包时使用；合并后不必加 `-m`。

---

## 6. 数据面状态（务必阅读）

- `with_transport` 构建现在会完成完整链路：
  CHIMERA UDP 握手 -> 服务器自动分配地址 -> Wintun 创建虚拟网卡 -> netsh 配置地址/DNS -> 双向包泵（TUN<->core）-> 半默认路由接管。
- 构建前请把 `wintun.dll` 放到 `ChimeraClient.exe` 同目录（CI artifact 已附带官方签名 DLL），并以管理员身份运行。
- 路由接管：`0.0.0.0/1` + `128.0.0.0/1` 走 Wintun，服务器 IP `/32` 走物理网卡；`store=active`。失败按非致命处理。待真机 `route print -4` 验收。
- 生产发布前还需要处理：代码签名、自动提权/UAC manifest、SmartScreen。
