package tunnel

import (
	"context"
	"net"
)

const socketBufferSize = 4 << 20 // 4 MiB

// ListenUDP binds a UDP socket with CHIMERA's anti-QoS socket tuning
// applied. All client and server sockets should be created through this
// helper instead of net.ListenPacket("udp", ...).
func ListenUDP(ctx context.Context, address string) (net.PacketConn, error) {
	var lc net.ListenConfig
	conn, err := lc.ListenPacket(ctx, "udp", address)
	if err != nil {
		return nil, err
	}
	tuneUDPConn(conn)
	return conn, nil
}
