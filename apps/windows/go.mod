module chimera/windows-client

go 1.25.0

require (
	chimera v0.0.0-00010101000000-000000000000
	github.com/wailsapp/wails/v2 v2.10.2
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	github.com/bep/debounce v1.2.1 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jchv/go-winloader v0.0.0-20210711035445-715c2860da7e // indirect
	github.com/labstack/echo/v4 v4.13.3 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leaanthony/go-ansi-parser v1.6.1 // indirect
	github.com/leaanthony/gosod v1.0.4 // indirect
	github.com/leaanthony/slicer v1.6.0 // indirect
	github.com/leaanthony/u v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/samber/lo v1.49.1 // indirect
	github.com/tkrajina/go-reflector v0.5.8 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/wailsapp/go-webview2 v1.0.19 // indirect
	github.com/wailsapp/mimetype v1.4.1 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
)

// chimera/core 是 monorepo 根模块中的核心传输层。
// 上面的 require chimera 配合 replace 指向仓库根目录；
// 启用 with_transport 构建标签时，Go 会解析到 ../../core。
// 在核心包尚未合并的提交上，go mod tidy 会因找不到 chimera/core 而失败，
// 此时请使用 `wails build -m` / `wails dev -m` 跳过 tidy，仅构建 stub 界面。
replace chimera => ../..
