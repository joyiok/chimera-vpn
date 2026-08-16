//go:build !windows

package bridge

import "errors"

// Install is Windows-only: route takeover needs netsh + IP Helper.
func (t *RouteTakeover) Install(tunName, tunIP, serverAddr string) error {
	return errors.New("route takeover is only available on Windows")
}

// Release is a no-op on non-Windows platforms.
func (t *RouteTakeover) Release() error { return nil }
