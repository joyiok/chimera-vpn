# Chimera Android 客户端

CHIMERA 是一个抗审查 VPN 协议。本目录是 Android 客户端工程（Kotlin + Android VpnService + Go 共享库 AAR）。

## 目录结构

```
apps/android/
├── settings.gradle.kts
├── build.gradle.kts
├── gradle.properties
├── build-android-core.sh
├── design/               # AI 生成的启动器图标与背景纹理源文件
├── README.md
└── app/
    ├── build.gradle.kts
    ├── libs/                  # bind.aar 构建后放在这里
    └── src/main/
        ├── AndroidManifest.xml
        ├── java/com/chimera/vpn/
        │   ├── MainActivity.kt
        │   ├── ChimeraVpnService.kt
        │   └── GoBind.kt
        └── res/
            ├── layout/activity_main.xml
            └── values/{strings.xml,colors.xml,themes.xml}
```

## 环境要求

- Android Studio（建议最新稳定版）
- JDK 17
- Android SDK Platform 35
- NDK（通过 Android Studio SDK Manager 安装，并确保 `ANDROID_NDK_HOME` 指向 NDK 目录）
- Go 1.22+，并确保 `$(go env GOPATH)/bin` 在 `PATH` 中
- gomobile / gobind（`build-android-core.sh` 会自动安装）
- 构建 Go 核心时设置 `GOFLAGS=-mod=mod`

## 构建 Go 核心（bind.aar）

Go 包 `chimera/bind` 合并到仓库根目录后，在 `apps/android/` 下执行：

```bash
cd /home/joy/chimera/apps/android
./build-android-core.sh
```

脚本会：

1. 安装 `golang.org/x/mobile/cmd/gomobile` 和 `gobind`（如尚未安装）；
2. 执行 `gomobile init`；
3. 从仓库根目录执行
   `GOFLAGS=-mod=mod gomobile bind -target=android -androidapi 26 -o apps/android/app/libs/bind.aar chimera/bind`。

在 `bind.aar` 生成之前，Android 工程也可以正常编译。`GoBind.kt` 会尝试通过
`Class.forName("bind.Bind")` 反射加载 Go 绑定；加载失败时返回明确错误：

```text
Go core not built: run ./build-android-core.sh first
```

## CI 构建

GitHub Actions job `android-apk` 跑在 `ubuntu-latest`（Android 不需要 macOS runner）：

1. 安装 JDK 17、Android SDK Platform 35、NDK r26d
2. `./build-android-core.sh`（`gomobile bind -androidapi 26`）
3. Gradle 8.9 `assembleDebug`
4. 上传 artifact `ChimeraClient-android-debug`（`app-debug.apk` + `bind.aar`）

PR / `main` 推送 / 手动 `workflow_dispatch` 都会跑。Debug APK 可 sideload，未做 Play 签名。

## 打开与运行

1. 启动 Android Studio，选择 **Open**，打开本目录 `apps/android`。
2. 等待 Gradle Sync 完成（首次同步会下载 AGP、Kotlin 和 AndroidX 依赖）。
3. 确认 `app/libs/bind.aar` 已存在（运行过 `build-android-core.sh`）；若不存在，工程仍可编译，
   但点击“连接”会提示先构建 Go 核心。
4. 连接 Android 设备或启动模拟器，点击 **Run**。
5. 在界面中填写服务器地址、Seed、Generation、PSK，点击“连接”，在系统弹窗中授权 VPN。
   本机 TUN 地址可留空：服务端开启 `client_cidr` 时会自动分配；未开启时使用该字段作为回退。

## VPN 路由说明

- 应用使用 `VpnService.Builder` 建立 TUN 接口：
  - 本地地址：优先使用服务器自动分配的地址（`10.99.0.2` 起）；服务端未分配时回退到界面填写的 `10.99.0.2/24`
  - 路由：`0.0.0.0/0`；尽力再加 IPv6 `::/0`（先 `fd99::2/64`，失败则跳过）
  - DNS：`1.1.1.1`、`8.8.8.8`
  - MTU：`1400`
- 建立成功后，`ChimeraVpnService` 调用 Go 绑定 `bind.Bind.start(...)`，立刻
  `socketFD` + `VpnService.protect(fd)`，再取分配地址并 `establish()` TUN。
  同时 `addDisallowedApplication(自身包名)` 作为双保险，避免 UDP 套接字绕进 TUN 自环。
  然后启动两条协程：
  1. `bind.Receive(handle)` → 写入 TUN 文件描述符（Go 协议栈发往设备的 IP 包）；
  2. TUN 文件描述符读取（单次最多 32767 字节）→ `bind.Send(handle, packet)`（设备发往协议栈的 IP 包）。
- 通知栏显示上下行流量，并提供「断开」「重连」；可添加快捷设置磁贴开关 VPN。
- 界面「手动填写」中可选传输（`udp` / `tcp` / `websocket`）：UDP 被 QoS 时选 `tcp`，需要 HTTP/WebSocket 伪装时选 `websocket`。
- 支持端口跳跃：填写端口数和偏移范围后，客户端会在 seed+generation 派生的端口序列上自动探测；需与服务端 `port_hop_count/port_hop_spread` 一致。
- 默认开启分流：`res/values/split_routes.xml` 里的公网 IPv4 白名单走 VPN，局域网/私网/链路本地/组播直连；关闭开关即全局模式。
- 入站静默 90s（`IdleMillis`）或 Receive 失败时，先对新 UDP 套接字 `protect`，再换 Go 会话；分配地址变了才重建 TUN。
- 断开时先关闭 TUN 文件描述符，再调用 `bind.Bind.stop(handle)`。

## 注意事项

- 前台服务通知使用 `ic_stat_vpn`；Android 13+ 会请求 `POST_NOTIFICATIONS`。
- 目标 SDK 为 35；前台服务使用 `specialUse` 类型（Android 14+ 要求）。
- 本工程在 Go 核心未合并前即可编译；运行时会通过反射加载 `bind.Bind`。
