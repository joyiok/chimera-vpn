// Command chimerad is the CHIMERA server for Linux. It multiplexes many
// clients over one UDP socket and bridges each client to one shared TUN
// interface:
//
// client IP packet -> UDP (generated protocol) -> chimera0 -> kernel routing
// kernel reply     -> chimera0 -> route by dst IP -> right client
//
// Every client must use a unique address inside the TUN subnet (for example
// 10.99.0.2, 10.99.0.3, ...). Interface addressing uses ip(8);
// NAT/IP-forwarding must be enabled by the operator (scripts/setup-nat.sh).
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"chimera/core"
	"chimera/internal/tun"
)

type tunConfig struct {
	Name    string `json:"name"`
	Address string `json:"address"` // CIDR, e.g. 10.99.0.1/24
	MTU     int    `json:"mtu"`
}

type serverConfig struct {
	Listen     string    `json:"listen"`
	SeedHex    string    `json:"seed_hex"`
	Generation uint64    `json:"generation"`
	PSKHex     string    `json:"psk_hex"`
	ClientCIDR string    `json:"client_cidr"`
	Tun        tunConfig `json:"tun"`

	// Cipher overrides the genome cipher draw ("" = default). Both
	// endpoints must agree; e.g. "chacha20-poly1305".
	Cipher string `json:"cipher"`

	// KeepaliveSec refreshes NAT mappings on idle links (0 = default 25s,
	// negative = disable).
	KeepaliveSec int `json:"keepalive_sec"`
	// IdleTimeoutSec reaps sessions quiet for that long (0 = disable).
	IdleTimeoutSec int `json:"idle_timeout_sec"`
	// RateLimitKBps caps each client's inbound rate in KiB/s (0 = off).
	RateLimitKBps int `json:"rate_limit_kbps"`
	// MaxSessions caps established clients (0 = default 256).
	MaxSessions int `json:"max_sessions"`
	// DisableDecoy turns off anti-probe decoy replies (default: decoys on).
	DisableDecoy bool `json:"disable_decoy"`
	// DisableShape turns off datagram length shaping (default: on).
	DisableShape bool `json:"disable_shape"`
}

func defaultConfig() serverConfig {
	return serverConfig{
		Listen:         "0.0.0.0:4789",
		ClientCIDR:     "10.99.0.0/24",
		KeepaliveSec:   25,
		IdleTimeoutSec: 180,
		MaxSessions:    256,
		Tun:            tunConfig{Name: "chimera0", Address: "10.99.0.1/24", MTU: 1400},
	}
}

func main() {
	configPath := flag.String("config", "/etc/chimera/server.json", "server JSON config path")
	flag.Parse()

	cfg := defaultConfig()
	raw, err := os.ReadFile(*configPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fatal(err)
	}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			fatal(fmt.Errorf("parse %s: %w", *configPath, err))
		}
	}

	coreCfg := core.Config{
		SeedHex:              cfg.SeedHex,
		Generation:           cfg.Generation,
		PSKHex:               cfg.PSKHex,
		ServerAddr:           cfg.Listen,
		ClientCIDR:           cfg.ClientCIDR,
		Cipher:               cfg.Cipher,
		KeepaliveInterval:    time.Duration(cfg.KeepaliveSec) * time.Second,
		IdleTimeout:          time.Duration(cfg.IdleTimeoutSec) * time.Second,
		RateLimitBytesPerSec: cfg.RateLimitKBps * 1024,
		MaxSessions:          cfg.MaxSessions,
		DisableDecoy:         cfg.DisableDecoy,
		DisableShape:         cfg.DisableShape,
	}
	normalized, err := core.NormalizeConfig(coreCfg)
	if err != nil {
		fatal(err)
	}
	coreCfg = normalized
	if cfg.Tun.Name == "" {
		cfg.Tun.Name = "chimera0"
	}
	if cfg.Tun.Address == "" {
		cfg.Tun.Address = "10.99.0.1/24"
	}
	if cfg.Tun.MTU == 0 {
		cfg.Tun.MTU = 1400
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, coreCfg, cfg.Tun); err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
	}
}

// clientRoute maps a client's tunnel source IP to its server-side Conn.
type clientRoute struct {
	mu     sync.RWMutex
	byIP   map[string]*core.Conn
	byConn map[*core.Conn]string
}

func newClientRoute() *clientRoute {
	return &clientRoute{byIP: map[string]*core.Conn{}, byConn: map[*core.Conn]string{}}
}

func (r *clientRoute) register(conn *core.Conn, ip string) *core.Conn {
	r.mu.Lock()
	defer r.mu.Unlock()
	if old, ok := r.byConn[conn]; ok && old != "" {
		delete(r.byIP, old)
	}
	var displaced *core.Conn
	if other, ok := r.byIP[ip]; ok && other != conn {
		displaced = other
		delete(r.byConn, other)
	}
	r.byConn[conn] = ip
	r.byIP[ip] = conn
	return displaced
}

func (r *clientRoute) lookup(ip string) *core.Conn {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIP[ip]
}

func (r *clientRoute) remove(conn *core.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ip := r.byConn[conn]
	delete(r.byConn, conn)
	if ip != "" {
		delete(r.byIP, ip)
	}
}

// packetIP returns the source or destination IP of a raw IPv4/IPv6 packet.
func packetIP(packet []byte, dst bool) string {
	if len(packet) == 0 {
		return ""
	}
	offset := 12
	if dst {
		offset = 16
	}
	switch packet[0] >> 4 {
	case 4:
		if len(packet) >= 20 {
			return net.IP(packet[offset : offset+4]).String()
		}
	case 6:
		if len(packet) >= 40 {
			if dst {
				return net.IP(packet[24:40]).String()
			}
			return net.IP(packet[8:24]).String()
		}
	}
	return ""
}

func run(ctx context.Context, coreCfg core.Config, tc tunConfig) error {
	dev, err := tun.Open(tc.Name)
	if err != nil {
		return fmt.Errorf("open TUN: %w (run as root or grant CAP_NET_ADMIN)", err)
	}
	defer dev.Close()
	log.Printf("TUN interface %s opened", dev.Name())

	if out, err := exec.Command("ip", "addr", "add", tc.Address, "dev", dev.Name()).CombinedOutput(); err != nil {
		return fmt.Errorf("ip addr add: %v: %s", err, out)
	}
	if out, err := exec.Command("ip", "link", "set", "dev", dev.Name(), "mtu", fmt.Sprint(tc.MTU), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set: %v: %s", err, out)
	}
	log.Printf("address %s, MTU %d", tc.Address, tc.MTU)

	srv, err := core.NewServer(coreCfg)
	if err != nil {
		return err
	}
	defer srv.Close()
	if err := srv.Start(); err != nil {
		return err
	}
	log.Printf("accepting clients on udp/%s fingerprint=%s", coreCfg.ServerAddr, fingerprint(coreCfg))

	routes := newClientRoute()
	errCh := make(chan error, 4)

	// TUN -> right client, selected by destination IP.
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				errCh <- fmt.Errorf("tun read: %w", err)
				return
			}
			dst := packetIP(buf[:n], true)
			conn := routes.lookup(dst)
			if conn == nil {
				continue // packet for an unknown client; drop silently
			}
			if err := conn.SendPacket(buf[:n]); err != nil {
				errCh <- fmt.Errorf("send to %s: %w", dst, err)
				return
			}
		}
	}()

	// Accept loop: one client pump per established session.
	go func() {
		for {
			conn, err := srv.Accept(ctx)
			if err != nil {
				if ctx.Err() == nil {
					errCh <- fmt.Errorf("accept: %w", err)
				}
				return
			}
			log.Printf("client %s connected", conn.RemoteAddr())
			go pumpClientToTun(conn, dev, routes, errCh)
		}
	}()

	// Ops heartbeat: session counts + authenticated-datagram length
	// histogram (groundwork for length shaping).
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				st := srv.Stats()
				log.Printf("stats: sessions=%d pending=%d decoys=%d frame_lens=%s",
					st.Established, st.Pending, st.Decoys, formatFrameLens(st.FrameLens))
			}
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		log.Println("shutting down")
		time.Sleep(100 * time.Millisecond)
		return nil
	}
}

func pumpClientToTun(conn *core.Conn, dev *tun.Device, routes *clientRoute, errCh chan<- error) {
	defer conn.Close()
	defer routes.remove(conn)
	registered := false
	if ip := conn.AssignedIP(); ip != "" {
		routes.register(conn, ip)
		registered = true
		log.Printf("client %s assigned TUN address %s", conn.RemoteAddr(), ip)
	}
	for {
		pkt, err := conn.ReceivePacket()
		if err != nil {
			if registered {
				errCh <- fmt.Errorf("client %s read: %w", conn.RemoteAddr(), err)
			}
			return
		}
		src := packetIP(pkt, false)
		if src != "" {
			if displaced := routes.register(conn, src); displaced != nil && displaced != conn {
				log.Printf("WARNING: %s re-registered TUN address %s previously used by %s",
					conn.RemoteAddr(), src, displaced.RemoteAddr())
			}
			registered = true
		}
		if _, err := dev.Write(pkt); err != nil {
			errCh <- fmt.Errorf("tun write: %w", err)
			return
		}
	}
}

func formatFrameLens(counts []uint64) string {
	bounds := []string{"<128", "<512", "<1024", "<1408", "<1500", ">=1500"}
	parts := make([]string, 0, len(counts))
	for i, c := range counts {
		name := "big"
		if i < len(bounds) {
			name = bounds[i]
		}
		parts = append(parts, fmt.Sprintf("%s:%d", name, c))
	}
	return strings.Join(parts, " ")
}

func fingerprint(cfg core.Config) string {
	seed, err := parseHex(cfg.SeedHex)
	if err != nil {
		return "unknown"
	}
	h := core.Sum256(append(seed, byte(cfg.Generation), byte(cfg.Generation>>8), byte(cfg.Generation>>16), byte(cfg.Generation>>24)))
	return fmt.Sprintf("%x", h[:4])
}

func parseHex(s string) ([]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, errors.New("expected 32 bytes")
	}
	return b, nil
}

func fatal(err error) {
	log.Fatalf("chimerad: %v", err)
}
