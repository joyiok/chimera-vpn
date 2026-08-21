//go:build !linux && !android && !windows

package tunnel

import "net"

func tuneUDPConn(net.PacketConn) {}
