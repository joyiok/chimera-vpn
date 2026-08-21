//go:build linux || android

package tunnel

import (
	"net"

	"golang.org/x/sys/unix"
)

// tuneUDPConn raises kernel socket buffers and forces DSCP/ToS back to
// best-effort (0) so middlebox QoS classifiers are less likely to bucket
// the flow as video/voice. Errors are deliberately ignored: the socket is
// still usable with OS defaults.
func tuneUDPConn(conn net.PacketConn) {
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return
	}
	_ = raw.Control(func(fd uintptr) {
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, socketBufferSize)
		_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, socketBufferSize)
		_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TOS, 0)
	})
}
