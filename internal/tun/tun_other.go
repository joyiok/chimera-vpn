//go:build !linux

package tun

import "errors"

// Device is unavailable on this platform.
type Device struct{}

func Open(name string) (*Device, error) {
	return nil, errors.New("TUN devices are only supported on Linux in this build")
}
func (d *Device) Name() string { return "" }
func (d *Device) Read(packet []byte) (int, error) {
	return 0, errors.New("TUN unavailable")
}
func (d *Device) Write(packet []byte) (int, error) {
	return 0, errors.New("TUN unavailable")
}
func (d *Device) Close() error { return nil }
