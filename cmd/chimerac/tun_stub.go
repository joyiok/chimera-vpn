//go:build !linux

package main

import "fmt"

func runVPN(cfg clientConfig, opt vpnOptions) error {
	_ = cfg
	_ = opt
	return fmt.Errorf("TUN VPN mode is Linux-only in this build; use -check to probe a server, or the Windows/Android clients")
}
