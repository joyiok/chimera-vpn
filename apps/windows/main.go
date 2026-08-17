// Package main 是 CHIMERA Windows 客户端的 Wails v2 入口。
//
// 技术栈：Go 后端 + WebView2 渲染的 HTML/JS/TS 前端。
// 前端构建产物由 Vite 输出到 frontend/dist，并通过 go:embed 打包进可执行文件。
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	app := NewChimeraApp()

	err := wails.Run(&options.App{
		Title:             "CHIMERA Windows 客户端",
		Width:             1080,
		Height:            720,
		MinWidth:          860,
		MinHeight:         560,
		HideWindowOnClose: true,
		AssetServer: &assetserver.Options{
			Assets: assets,
		},
		BackgroundColour: &options.RGBA{R: 13, G: 17, B: 23, A: 255},
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		Bind: []interface{}{
			app,
		},
	})

	if err != nil {
		log.Fatalf("[CHIMERA] Wails 启动失败: %v", err)
	}
}
