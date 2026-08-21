// Package bind exposes the CHIMERA core through a gomobile-friendly API.
//
// Build for Android:
//
// gomobile bind -target=android -androidapi 26 -o bind.aar chimera/bind
//
// The API is intentionally tiny: Start/AssignedIP/Stop/Send/Receive/SocketFD/IdleMillis/BytesSent/BytesRecv.
// The Android VpnService shell polls Receive on a worker thread and pushes
// outbound IP packets through Send. Android must call SocketFD after Start
// and VpnService.protect(fd) before establish().
package bind

import (
	"context"
	"fmt"
	"sync"
	"time"

	"chimera/core"
)

var (
	mu      sync.Mutex
	nextID  int64 = 1
	clients       = map[int64]*core.Client{}
)

// Start creates a UDP client tunnel. Returns a handle for Stop/Send/Receive.
func Start(seedHex string, generation int64, pskHex string, serverAddr string) (int64, error) {
	return start(seedHex, generation, pskHex, serverAddr, "udp", 1, 0)
}

// StartTransport creates a client tunnel over "udp" or "tcp".
// TCP uses the same generated protocol bytes in 2-byte stream frames and is
// the recommended mode on networks that aggressively QoS/throttle UDP.
func StartTransport(seedHex string, generation int64, pskHex string, serverAddr string, transport string) (int64, error) {
	return start(seedHex, generation, pskHex, serverAddr, transport, 1, 0)
}

// StartTransportWithHop is StartTransport plus deterministic port hopping.
// count<=1 disables hopping; spread<=0 uses the core default (2048).
func StartTransportWithHop(seedHex string, generation int64, pskHex string, serverAddr string, transport string, hopCount int64, hopSpread int64) (int64, error) {
	return start(seedHex, generation, pskHex, serverAddr, transport, hopCount, hopSpread)
}

func start(seedHex string, generation int64, pskHex string, serverAddr string, transport string, hopCount int64, hopSpread int64) (int64, error) {
	if generation < 0 {
		return 0, fmt.Errorf("generation must be >= 0")
	}
	c, err := core.NewClient(core.Config{
		SeedHex:           seedHex,
		Generation:        uint64(generation),
		GenerationWindow:  2,
		JitterMax:         20 * time.Millisecond,
		KeepaliveInterval: 25 * time.Second,
		PSKHex:            pskHex,
		ServerAddr:        serverAddr,
		Transport:         transport,
		PortHopCount:      int(hopCount),
		PortHopSpread:     int(hopSpread),
	})
	if err != nil {
		return 0, err
	}
	if err := c.Start(); err != nil {
		return 0, err
	}

	mu.Lock()
	defer mu.Unlock()
	h := nextID
	nextID++
	clients[h] = c
	return h, nil
}

// AssignedIP waits for the server to assign this client a TUN address.
func AssignedIP(handle int64) (string, error) {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return "", fmt.Errorf("unknown handle %d", handle)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.AssignedIP(ctx)
}

// Stop closes the tunnel and releases the handle.
func Stop(handle int64) error {
	mu.Lock()
	c := clients[handle]
	delete(clients, handle)
	mu.Unlock()
	if c == nil {
		return fmt.Errorf("unknown handle %d", handle)
	}
	return c.Close()
}

// Send forwards one raw IP packet into the tunnel.
func Send(handle int64, packet []byte) error {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return fmt.Errorf("unknown handle %d", handle)
	}
	return c.SendPacket(packet)
}

// Receive blocks until a raw IP packet arrives from the tunnel.
func Receive(handle int64) ([]byte, error) {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return nil, fmt.Errorf("unknown handle %d", handle)
	}
	return c.ReceivePacket()
}

// SocketFD returns the UDP socket file descriptor for this handle so the
// Android VpnService can call protect(fd) before establishing the TUN.
// The fd is still owned by the Go client; do not close it.
func SocketFD(handle int64) (int, error) {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return -1, fmt.Errorf("unknown handle %d", handle)
	}
	return c.UDPFileDescriptor()
}

// IdleMillis is inbound silence in milliseconds (see core.Client.IdleFor).
// Platform watchdogs treat several keepalive intervals as link loss.
func IdleMillis(handle int64) (int64, error) {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return 0, fmt.Errorf("unknown handle %d", handle)
	}
	return c.IdleFor().Milliseconds(), nil
}

// BytesSent is TUN payload bytes this handle has sent.
func BytesSent(handle int64) (int64, error) {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return 0, fmt.Errorf("unknown handle %d", handle)
	}
	sent, _ := c.Bytes()
	return int64(sent), nil
}

// BytesRecv is TUN payload bytes this handle has received.
func BytesRecv(handle int64) (int64, error) {
	mu.Lock()
	c := clients[handle]
	mu.Unlock()
	if c == nil {
		return 0, fmt.Errorf("unknown handle %d", handle)
	}
	_, recv := c.Bytes()
	return int64(recv), nil
}
