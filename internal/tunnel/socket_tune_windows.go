//go:build windows

package tunnel

import (
	"net"

	"golang.org/x/sys/windows"
)

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
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_RCVBUF, socketBufferSize)
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_SNDBUF, socketBufferSize)
		_ = windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_IP, windows.IP_TOS, 0)
	})
}
