//go:build linux

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func watchUSR1(ctx context.Context, dump func()) {
	if dump == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			dump()
		}
	}
}
