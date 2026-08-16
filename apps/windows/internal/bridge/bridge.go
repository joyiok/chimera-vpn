// Package bridge owns the Windows TUN data plane. platform-specific files
// implement Start/Close; this file defines the shared types.
package bridge

import "sync"

// Sender pushes one raw IP packet into the encrypted core.
type Sender func([]byte) error

// Receiver returns the next raw IP packet from the encrypted core.
type Receiver func() ([]byte, error)

// platformDevice matches golang.zx2c4.com/wireguard/tun.Device.
type platformDevice interface {
	Read(bufs [][]byte, sizes []int, offset int) (int, error)
	Write(bufs [][]byte, offset int) (int, error)
	Close() error
}

// Bridge is an active TUN <-> core packet pump.
type Bridge struct {
	dev       platformDevice
	ip        string
	send      Sender
	recv      Receiver
	done      chan struct{}
	closeOnce sync.Once
}

// Start creates the virtual adapter, configures it, and starts both loops.
func Start(ip string, mtu int, send Sender, recv Receiver) (*Bridge, error) {
	return platformStart(ip, mtu, send, recv)
}

// Done is closed when both loops have exited.
func (b *Bridge) Done() <-chan struct{} { return b.done }

// Close stops the data plane. It returns immediately; loop goroutines unwind
// as soon as the transport socket is also closed.
func (b *Bridge) Close() error {
	var err error
	b.closeOnce.Do(func() { err = b.dev.Close() })
	return err
}
