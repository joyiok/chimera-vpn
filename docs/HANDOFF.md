# CHIMERA 开发交接文档

> 仓库：https://github.com/joyiok/chimera-vpn
> 分支：`main`（Public）
> 状态：可编译、可测试的研究型原型，**不是生产 VPN**。

## 10 分钟快速了解

CHIMERA 的核心思想来自 [UPGen](https://www.usenix.org/biblio/fake-title-653)：
**不伪装成已知协议，而是从一颗 256-bit 种子确定性地生成一个全新的、结构合理的加密协议。**
每台服务器、每一代（generation）的协议都不同；审查者无法训练一个通用的协议指纹。

仓库是一个 Go monorepo：

```text
seed(256bit) + generation
        │
        ▼
internal/genome      生成协议基因组（握手模式/字段布局/编码/padding/cipher）
        │
        ▼
internal/compiler    把基因组编译成可执行状态机（流/包两种模式）
        │
        ▼
internal/tunnel      UDP 握手 + 多客户端复用 + packet tunnel
        │
        ▼
core / bind          跨平台 Go API + gomobile 移动端绑定
        │
        ├── cmd/chimerad        Linux 服务端（TUN + 地址池 + 路由）
        ├── apps/windows        Windows Wails GUI + Wintun 数据面
        ├── apps/android        Android VpnService 客户端
        └── apps/ios            iOS NEPacketTunnelProvider 客户端
```

## 当前状态一页表

| 模块 | 状态 | 验证程度 |
|---|---|---|
| 协议生成/握手/AEAD | ✅ 完成 | `go test -race` 通过 |
| UDP 多客户端复用 | ✅ 完成 | 3 客户端并发测试 |
| 地址自动分配 | ✅ 完成 | `10.99.0.0/24` 池测试 |
| Linux 服务端 | ✅ 代码完成 | 编译/静态检查；TUN 需 root 实机 |
| Windows GUI | ✅ 控制面 + Wintun 包泵 + 默认路由接管 | Linux 上交叉编译到 Windows 通过；路由需真机验收 |
| Android/iOS | ⚠️ 源码骨架 | 未真机构建 |
| Windows 默认路由接管 | ✅ 代码完成 | 纯逻辑单测通过；`route print` 验收待真机 |
| 长期丢包恢复 | ✅ 完成 | ACK/SKIP 控制载荷；`-race` 测试含丢卡恢复用例 |
| CI | ✅ 完成 | 根模块 + Windows 交叉编译 + **windows-latest Wails GUI 产物** + gobind |
| ChaCha20-Poly1305 | ✅ 完成 | `cipher` 配置强制覆盖；端到端 + 不匹配拒连测试 |
| 握手重放防护 | ✅ 完成 | 流模式 64 序号位图，录制重放被拒 |
| NAT keepalive / 空闲回收 / 限速 | ✅ 完成 | `keepalive_sec`/`idle_timeout_sec`/`rate_limit_kbps` 配置 |
| 连接配额 | ✅ 完成 | `max_sessions`（chimerad 默认 256） |
| 探测诱饵 | ✅ 完成 | 非法首包回 decoy 物种；限速+体积帽 |
| 包长整形 | ✅ 完成 | 128/512/1024/1452 阶梯；无 pad 基因型跳过 |
| Android/iOS 套接字绕过 TUN | ✅ 代码完成 | Android `protect(fd)`；iOS `/32` excludedRoutes；待真机 |
| 时序抖动 | ✅ 完成 | 截断指数 IAT，上限 20ms；对齐 obfs4/CCS 2015 |
| 服务端 generation 窗口 | ✅ 完成 | 并行接受 gen…gen+N；client-first 可轮换 |
| chimerad 生产运维 | ✅ 完成 | 单客户端断开不杀进程；TUN 地址幂等；`-check-config`；systemd 硬化 |

## 接手后先做什么

1. `git clone https://github.com/joyiok/chimera-vpn`
2. 安装 Go 1.24+
3. `go test -race ./...` —— 必须全绿
4. 阅读顺序：
   - `docs/ARCHITECTURE.md`（代码地图与数据流）
   - `docs/PROTOCOL.md`（线上格式与密码学）
   - `docs/BUILD.md`（各平台构建）
   - `docs/ROADMAP.md`（下一步与实现提示）
5. 从 ROADMAP 的 **任务 4：Android/iOS 真机联调** 或车道 B/C 开始；
   若在 Windows 真机旁，先验收路由接管（`route print -4`）。
   生产部署：`chmod 0600` 配置、`chimerad -check-config`、`deploy/chimerad.service`。

## 提交规范

- 模块化提交：`core: ...` / `windows: ...` / `android: ...` / `docs: ...`
- 每个提交前跑：
  ```bash
  gofmt -l .          # 除 frontend/node_modules 外应为空
  go vet ./...
  go test -race ./...
  cd apps/windows && go test ./... && go test -tags with_transport ./...
  ```
- 推送前确保 `git status` 无未跟踪二进制（Wails 构建会生成 `windows-client.exe`，已加入 .gitignore）。

## 文档索引

- [ARCHITECTURE.md](ARCHITECTURE.md) —— 代码地图、数据流、核心 API
- [PROTOCOL.md](PROTOCOL.md) —— 线上协议、帧格式、握手、密码学
- [BUILD.md](BUILD.md) —— 各平台构建/运行/真机联调
- [ROADMAP.md](ROADMAP.md) —— 现状与下一步实现提示
- [SECURITY.md](SECURITY.md) —— 威胁模型与已知限制
