//go:build linux

// Package tun wraps a Linux TUN device for the CHIMERA server and desktop
// clients. TUN mode carries raw IPv4/IPv6 packets without PI headers.
package tun

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Device is an open TUN interface.
type Device struct {
	file *os.File
	name string
}

// Open creates (or attaches to) a TUN device. If name is empty the kernel
// picks a tun%d name. The interface is left down; the caller configures an
// address with ip(8) or netlink.
func Open(name string) (*Device, error) {
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr, err := unix.NewIfreq(name)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		unix.Close(fd)
		return nil, err
	}

	ifName := ifr.Name()
	if ifName == "" {
		unix.Close(fd)
		return nil, errors.New("kernel returned empty TUN name")
	}
	return &Device{file: os.NewFile(uintptr(fd), "/dev/net/tun:"+ifName), name: ifName}, nil
}

// Name returns the allocated interface name.
func (d *Device) Name() string { return d.name }

// Read reads one raw IP packet.
func (d *Device) Read(packet []byte) (int, error) { return d.file.Read(packet) }

// Write writes one raw IP packet.
func (d *Device) Write(packet []byte) (int, error) { return d.file.Write(packet) }

// Close destroys the file descriptor; the kernel removes the interface when
// the last fd closes.
func (d *Device) Close() error {
	if d.file == nil {
		return nil
	}
	err := d.file.Close()
	d.file = nil
	return err
}
