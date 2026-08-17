# 部署一页纸

两端必须使用**同一** `seed_hex`、`psk_hex`、`generation`（以及可选的 `cipher`）。
握手封面与认证 knock 不向后兼容旧构建。

这是自建研究型 VPN 的操作步骤，不是“抗 GFW 保证”。威胁模型见 [SECURITY.md](SECURITY.md)。

## 0. 生成密钥

```bash
go run ./cmd/gencompiler \
  -seed 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
# 不传 -seed 会打印随机 32 字节，务必保存
```

PSK 另生成 32 随机字节（64 hex），不要复用 seed。

## 1. Linux 服务端

```bash
sudo mkdir -p /etc/chimera /var/lib/chimera
sudo cp configs/server.example.json /etc/chimera/server.json
sudo chmod 0600 /etc/chimera/server.json   # 文件里是 PSK
# 编辑 listen / seed_hex / psk_hex / tun.address / client_cidr

CGO_ENABLED=0 go build -o /usr/local/bin/chimerad ./cmd/chimerad
sudo /usr/local/bin/chimerad -config /etc/chimera/server.json -check-config
# 期望：config ok … genome=… cover_len=24..32

sudo install -m 644 deploy/chimerad.service /etc/systemd/system/
sudo ./scripts/setup-nat.sh eth0          # 换成实际出口网卡
sudo systemctl enable --now chimerad
journalctl -u chimerad -f
```

防火墙放行 `server.json` 里的 UDP 端口（默认 4789）。

## 2. Windows 客户端

1. GitHub Actions 打开最新绿色 run，下载 artifact `ChimeraClient-windows-amd64`
   （`ChimeraClient.exe` + 官方签名 `wintun.dll`）。PR / `main` / `workflow_dispatch` 都会构建。
2. 两个文件放同一目录，**管理员**运行 exe。
3. 填入与服务器相同的 seed / generation / PSK / `host:port`。
   字段示例见 `configs/client.example.json`（GUI 会写到 exe 旁 `chimera-config.json`，权限 0600）。
4. 未代码签名，SmartScreen 可能提示；见 `apps/windows/build/README.md`。
5. 连通后 `route print -4` 应看到 `0.0.0.0/1` 与 `128.0.0.0/1` 走 Wintun，服务器 IP `/32` 走物理网卡。

本机构建：`apps/windows` 下 `wails build -tags with_transport`（需要 Windows + CGO）。

## 3. Android 客户端

1. GitHub Actions job `android-apk`（`ubuntu-latest`）下载 artifact
   `ChimeraClient-android-debug`（`app-debug.apk` + `bind.aar`）。
2. 允许未知来源后 sideload `app-debug.apk`。这是 debug 签名，不是 Play 发布包。
3. 填入与服务器相同的 seed / generation / PSK / `host:port`。
4. **尚未真机验收**；`VpnService.protect(fd)` 已接进源码。

本机构建：`apps/android/build-android-core.sh` 后 Android Studio 或 `gradle assembleDebug`。

## 4. iOS 核心（不是 IPA）

1. GitHub Actions job `ios-xcframework`（`macos-latest`）下载 artifact
   `ChimeraBind-ios-xcframework`。
2. 用 Xcode 把 `ChimeraBind.xcframework` 链到 `ChimeraPacketTunnel`，配好 Team /
   App Group / Network Extension 后真机运行。CI **不会**出已签名 IPA。
3. **尚未真机验收**；服务器地址 `/32` excludedRoutes 已接进源码。

本机构建：macOS 上 `apps/ios/build-ios-core.sh`。

## 5. 不要做的事

- 不要把配置文件 chmod 成 0644 或提交到 git。
- 不要只升级一端。
- 不要把一次 `go test` 绿灯理解成已经绕过国家级审查。
