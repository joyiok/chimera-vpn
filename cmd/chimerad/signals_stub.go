//go:build !linux

package main

import "context"

func watchUSR1(ctx context.Context, dump func()) {
	<-ctx.Done()
}
