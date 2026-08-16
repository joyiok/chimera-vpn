# build 目录说明

## 脚本

- `build.bat`：生产构建。默认构建 stub 版本；传 `with_transport` 参数可构建真实传输层。
- `dev.bat`：开发模式。默认 stub；传 `with_transport` 参数可启用真实传输层。

脚本会自动检测 `..\..\core\core.go` 是否存在：
存在时使用标准 `wails build` / `wails dev`；不存在时自动追加 `-m`
跳过 `go mod tidy`，避免因 `chimera/core` 缺失导致 tidy 失败。

```bat
cd /d %~dp0\..
build\build.bat
build\build.bat with_transport
build\dev.bat
build\dev.bat with_transport
```

输出文件位于 `build\bin\ChimeraClient.exe`（由 Wails CLI 生成）。

## Windows Defender / 代码签名（生产注意事项）

1. **SmartScreen 提示**：未签名的本地构建 exe 首次运行时可能触发
   “Windows 已保护你的电脑”。这是 Windows 对未签名/低信誉二进制的正常行为，
   不是代码错误。开发阶段可点击“更多信息 → 仍要运行”。
2. **代码签名**：对外发布前必须使用代码签名证书（OV/EV）签名，否则
   SmartScreen 会显示未知发布者。推荐使用 SHA-256 摘要并添加 RFC 3161 时间戳：
   ```bat
   signtool sign /fd SHA256 /a /tr http://timestamp.digicert.com /td SHA256 ^
     build\bin\ChimeraClient.exe
   ```
3. **防病毒误报**：VPN/代理类客户端容易触发启发式扫描。签名能显著减少误报；
   必要时向 Microsoft 提交误报分析（security.microsoft.com）。
4. **不要在生产环境使用 stub 版本**：默认构建不包含真实协议传输层，
   Start 会返回 `transport not compiled`。生产版本请务必使用
   `build.bat with_transport` 并在已合并 `chimera/core` 的代码库上构建。
5. **版本信息与图标**：正式发布建议在 `wails.json` 中补充 `info` 段，
   并通过 Wails 的图标/资源能力嵌入版本号和图标，避免可执行文件缺少
   公司名称、版本等元数据。
