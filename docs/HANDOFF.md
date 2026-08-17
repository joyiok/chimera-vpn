# CHIMERA 开发交接文档

> 仓库：https://github.com/joyiok/chimera-vpn
> 分支：`main`（Public）
> 状态：可编译、可测试的研究型原型；数据面与守护进程已按自建 VPN 收紧，**不是**已验证的抗 GFW 产品。
> 睡醒后先 `bash scripts/selftest.sh`（不用 root），再按 [DEPLOY.md](DEPLOY.md) 跑服务端 + Linux `chimerac` / Windows / Android artifact（iOS 是 XCFramework，不是 IPA）。

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
        ├── cmd/chimerac        Linux 客户端（-check / TUN / 自动重连）
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
| Linux 服务端 | ✅ 代码完成 | 编译/静态检查；TUN 需 root 实机；`scripts/selftest.sh` 覆盖 -no-tun 握手+回显 |
| Linux CLI 客户端 | ✅ 代码完成 | `chimerac -check` + selftest；TUN/默认路由需 root；入站静默 90s 自动重连 |
| Windows GUI | ✅ 控制面 + 托盘 + 流量图 + 入口列表 | Linux 交叉编译；Wails 真机托盘/路由待验收 |
| Android/iOS | ⚠️ CI 可出包 | protect / excludedRoutes / IdleMillis 重连已接；真机与 IPA 签名未做 |
| Windows 默认路由接管 | ✅ 代码完成 | 纯逻辑单测通过；`route print` 验收待真机 |
| 长期丢包恢复 | ✅ 完成 | ACK/SKIP 控制载荷；`-race` 测试含丢卡恢复用例 |
| CI | ✅ 完成 | 根模块 + **userspace selftest** + Linux CLI artifact + Windows 交叉编译 + **windows-latest Wails GUI** + **ubuntu Android debug APK** + **macos iOS XCFramework** + gobind |
| ChaCha20-Poly1305 | ✅ 完成 | `cipher` 配置强制覆盖；端到端 + 不匹配拒连测试 |
| 握手重放防护 | ✅ 完成 | 流模式 64 序号位图，录制重放被拒 |
| NAT keepalive / 空闲回收 / 限速 | ✅ 完成 | `keepalive_sec`/`idle_timeout_sec`/`rate_limit_kbps` 配置 |
| 连接配额 | ✅ 完成 | `max_sessions`（chimerad 默认 256） |
| 探测诱饵 | ✅ 完成 | 非法首包回 decoy 物种；限速+体积帽 |
| 包长整形 | ✅ 完成 | 128/512/1024/1452 阶梯；无 pad 基因型跳过 |
| Android/iOS 套接字绕过 TUN | ✅ 代码完成 | Android `protect(fd)`；iOS `/32` excludedRoutes；IdleMillis 重连；待真机 |
| 时序抖动 | ✅ 完成 | 截断指数 IAT，上限 20ms；对齐 obfs4/CCS 2015 |
| 服务端 generation 窗口 | ✅ 完成 | 并行接受 gen…gen+N；client-first 可轮换 |
| chimerad 生产运维 | ✅ 完成 | 单客户端断开不杀进程；TUN 地址幂等；`-check-config`；systemd 硬化 |
| FEP 握手封面 | ✅ 完成 | 随机可打印前缀 24–32 字节；Wu et al. USENIX Sec 2023 Ex2/Ex4 |
| 认证 knock | ✅ 完成 | server-first 需 PSK-MAC；随机探针不再拿到真实首帧 |
| 握手重放表 | ✅ 完成 | 已认证首包/knock SHA-256；默认可落盘；IMC 2020 同类重放不建第二会话 |

## 接手后先做什么

1. `git clone https://github.com/joyiok/chimera-vpn`
2. 安装 Go 1.24+
3. `go test -race ./...` —— 必须全绿
4. `bash scripts/selftest.sh` —— 不用 root，验证本机二进制能握手、拿地址、打通数据面
5. 阅读顺序：
   - `docs/ARCHITECTURE.md`（代码地图与数据流）
   - `docs/PROTOCOL.md`（线上格式与密码学）
   - `docs/BUILD.md`（各平台构建）
   - `docs/ROADMAP.md`（下一步与实现提示）
6. 从 ROADMAP 的 **任务 4：Android/iOS 真机联调** 或车道 B/C 开始；
   若在 Linux 旁，先 `chimerac -check` 再考虑 `-take-route`。
   若在 Windows 真机旁，先验收路由接管（`route print -4`）。
   生产部署：`chmod 0600` 配置、`chimerad -check-config`、`deploy/chimerad.service`；
   一页操作见 [DEPLOY.md](DEPLOY.md)。

## 提交规范

- 模块化提交：`core: ...` / `windows: ...` / `android: ...` / `docs: ...`
- 每个提交前跑：
  ```bash
  gofmt -l .          # 除 frontend/node_modules 外应为空
  go vet ./...
  go test -race ./...
  bash scripts/selftest.sh
  cd apps/windows && go test ./... && go test -tags with_transport ./...
  ```
- 推送前确保 `git status` 无未跟踪二进制（Wails 构建会生成 `windows-client.exe`，已加入 .gitignore）。

## 文档索引

- [ARCHITECTURE.md](ARCHITECTURE.md) —— 代码地图、数据流、核心 API
- [PROTOCOL.md](PROTOCOL.md) —— 线上协议、帧格式、握手、密码学
- [BUILD.md](BUILD.md) —— 各平台构建/运行/真机联调
- [DEPLOY.md](DEPLOY.md) —— 服务端 + Windows 客户端一页部署
- [ROADMAP.md](ROADMAP.md) —— 现状与下一步实现提示
- [SECURITY.md](SECURITY.md) —— 威胁模型与已知限制
