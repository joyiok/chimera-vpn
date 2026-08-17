package main

import (
	"context"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

func runtimeWindowHide(ctx context.Context) {
	if ctx != nil {
		runtime.WindowHide(ctx)
	}
}

func runtimeWindowShow(ctx context.Context) {
	if ctx != nil {
		runtime.WindowShow(ctx)
	}
}

func runtimeQuit(ctx context.Context) {
	if ctx != nil {
		runtime.Quit(ctx)
	}
}
