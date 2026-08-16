// Package bind exposes the CHIMERA core through a gomobile-friendly API.
//
// Build for Android:
//
// gomobile bind -target=android -o bind.aar chimera/bind
//
// Build for iOS:
//
// gomobile bind -target=ios,iossimulator,macos -o ChimeraBind.xcframework chimera/bind
//
// The API is intentionally tiny: Start/Stop/Send/Receive. Mobile VpnService
// and NEPacketTunnelProvider shells poll Receive on a worker thread and push
// outbound IP packets through Send.
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

// Start creates a client tunnel. Returns a handle for Stop/Send/Receive.
func Start(seedHex string, generation int64, pskHex string, serverAddr string) (int64, error) {
	if generation < 0 {
		return 0, fmt.Errorf("generation must be >= 0")
	}
	c, err := core.NewClient(core.Config{
		SeedHex:    seedHex,
		Generation: uint64(generation),
		PSKHex:     pskHex,
		ServerAddr: serverAddr,
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
