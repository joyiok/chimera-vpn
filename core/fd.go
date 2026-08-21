package core

import (
	"errors"
	"net"
	"syscall"
)

// UDPFileDescriptor returns the underlying transport socket fd so a platform
// shell can exclude it from the VPN path (Android VpnService.protect). Both
// UDP and TCP stream transports expose this through syscall.Conn.
// The fd stays owned by the client; the caller must not close it.
func (c *Client) UDPFileDescriptor() (int, error) {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return -1, errors.New("client not started")
	}
	return packetConnFD(conn)
}

func packetConnFD(c net.PacketConn) (int, error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return -1, errors.New("packet conn does not expose a file descriptor")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return -1, err
	}
	var fd int
	if err := raw.Control(func(sysfd uintptr) {
		fd = int(sysfd)
	}); err != nil {
		return -1, err
	}
	if fd < 0 {
		return -1, errors.New("invalid file descriptor")
	}
	return fd, nil
}
