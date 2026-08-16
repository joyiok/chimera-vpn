// Package core is the cross-platform CHIMERA client/server API. Windows,
// Android and iOS shells call into this package (or into bind, which wraps
// it for gomobile).
package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
	"chimera/internal/tunnel"
)

// Config holds deployment parameters. Seed and PSK are hex-encoded byte
// strings; the seed defines the protocol species, the PSK authenticates the
// handshake.
type Config struct {
	SeedHex    string
	Generation uint64
	PSKHex     string
	ServerAddr string
	ClientCIDR string // server-only: client TUN pool, e.g. 10.99.0.0/24
	// Cipher overrides the genome's cipher draw ("" = genome default).
	// genome.CipherChaCha20P1305 suits clients without AES acceleration;
	// both endpoints must configure the same value.
	Cipher string
	// KeepaliveInterval refreshes NAT mappings on idle links (< 0 disables,
	// 0 uses tunnel.DefaultKeepaliveInterval).
	KeepaliveInterval time.Duration
	// GenerationWindow: when the handshake times out, probe this many
	// successive generations (server-side rotation without redeploying
	// clients). 0 probes nothing.
	GenerationWindow uint64
	// IdleTimeout (server) reaps sessions quiet for that long (<= 0 =
	// never reap).
	IdleTimeout time.Duration
	// RateLimitBytesPerSec (server) caps each session's inbound datagram
	// rate (<= 0 = unlimited).
	RateLimitBytesPerSec int
	// MaxSessions (server) caps established clients. 0 = unlimited.
	MaxSessions int
	// DisableDecoy (server) turns off anti-probe decoy replies. Decoys
	// are on by default: illegal first packets get a frame of a disjoint
	// generated protocol, rate-limited per source and globally.
	DisableDecoy bool
	// DisableShape turns off datagram length shaping (default: pad frames
	// to compiler.DefaultShapeBuckets).
	DisableShape bool
}

// NormalizeConfig validates and decodes a Config.
func NormalizeConfig(cfg Config) (Config, error) {
	seed, err := parseHex32(cfg.SeedHex, "seed")
	if err != nil {
		return cfg, err
	}
	psk, err := parseHex32(cfg.PSKHex, "psk")
	if err != nil {
		return cfg, err
	}
	if strings.TrimSpace(cfg.ServerAddr) == "" {
		return cfg, errors.New("server address is empty")
	}
	if cfg.Cipher != "" && !genome.KnownCipher(cfg.Cipher) {
		return cfg, fmt.Errorf("unknown cipher %q", cfg.Cipher)
	}
	cfg.SeedHex = hex.EncodeToString(seed)
	cfg.PSKHex = hex.EncodeToString(psk)
	return cfg, nil
}

func parseHex32(s, name string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(s), "0x", "")
	b, err := hex.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("%s must be hex: %w", name, err)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("%s must be 32 bytes (64 hex chars), got %d", name, len(b))
	}
	return b, nil
}

// Client is one VPN endpoint.
type Client struct {
	cfg  Config
	mu   sync.Mutex
	conn net.PacketConn
	tun  *tunnel.PacketTunnel
	gen  uint64 // generation the current session actually used
}

// NewClient prepares a client; Start establishes the tunnel.
func NewClient(cfg Config) (*Client, error) {
	cfg, err := NormalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

// Start runs the generated UDP handshake with the configured server. If
// GenerationWindow > 0 and the handshake times out, the next generations
// are probed in order, so a server that rotated its generation is picked
// up automatically.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tun != nil {
		return errors.New("client already started")
	}

	window := c.cfg.GenerationWindow
	var lastErr error
	for attempt := uint64(0); attempt <= window; attempt++ {
		gen := c.cfg.Generation + attempt
		tun, conn, err := startSession(c.cfg, gen)
		if err == nil {
			c.conn = conn
			c.tun = tun
			c.gen = gen
			return nil
		}
		lastErr = err
		if !errors.Is(err, tunnel.ErrHandshakeTimeout) {
			return err // configuration or network error: probing won't help
		}
	}
	return lastErr
}

// startSession performs one full dial: socket, genome, handshake.
func startSession(cfg Config, generation uint64) (*tunnel.PacketTunnel, net.PacketConn, error) {
	seed, _ := parseHex32(cfg.SeedHex, "seed")
	psk, _ := parseHex32(cfg.PSKHex, "psk")
	remote, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, nil, err
	}

	g, err := genome.GenerateWithCipher(seed, generation, cfg.Cipher)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	sess, err := tunnel.ClientHandshake(conn, remote, h)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	t := tunnel.NewPacketTunnel(conn, remote, sess)
	if !cfg.DisableShape {
		t.SetShapeBuckets(compiler.DefaultShapeBuckets)
	}
	t.SetKeepalive(cfg.KeepaliveInterval)
	return t, conn, nil
}

// SendPacket forwards one raw IP packet into the tunnel.
func (c *Client) SendPacket(packet []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tun == nil {
		return errors.New("client not started")
	}
	return c.tun.SendPacket(packet)
}

// ReceivePacket blocks until an IP packet arrives from the tunnel.
func (c *Client) ReceivePacket() ([]byte, error) {
	c.mu.Lock()
	t := c.tun
	c.mu.Unlock()
	if t == nil {
		return nil, errors.New("client not started")
	}
	return t.ReceivePacket()
}

// AssignedIP waits for the server to assign this client a TUN address.
// ctx should bound the wait (e.g. 5 seconds).
func (c *Client) AssignedIP(ctx context.Context) (string, error) {
	c.mu.Lock()
	t := c.tun
	c.mu.Unlock()
	if t == nil {
		return "", errors.New("client not started")
	}
	pkt, err := t.WaitControl(ctx)
	if err != nil {
		return "", err
	}
	if len(pkt) == 0 {
		return "", errors.New("empty address assignment")
	}
	return string(pkt), nil
}

// Close tears the tunnel down.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tun != nil {
		err := c.tun.Close()
		c.tun = nil
		c.conn = nil
		return err
	}
	return nil
}

// Config returns the normalized configuration.
func (c *Client) Config() Config { return c.cfg }

// Generation returns the generation the established session actually
// uses; with a probe window this can be higher than the configured one.
func (c *Client) Generation() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gen
}

// IdleFor reports how long the link has been quiet. A healthy link with
// keepalives never exceeds roughly one interval; multiples of it indicate
// loss. Returns 0 when not started.
func (c *Client) IdleFor() time.Duration {
	c.mu.Lock()
	t := c.tun
	c.mu.Unlock()
	if t == nil {
		return 0
	}
	return t.IdleFor()
}

// Server multiplexes many generated-protocol clients over one UDP socket.
type Server struct {
	cfg Config

	mu     sync.Mutex
	conn   net.PacketConn
	mux    *tunnel.ServerMux
	cancel context.CancelFunc
	done   chan struct{}
	pool   *addressPool
}

// NewServer prepares a server; Start binds and begins accepting clients.
func NewServer(cfg Config) (*Server, error) {
	cfg, err := NormalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg}
	if cfg.ClientCIDR != "" {
		pool, err := newAddressPool(cfg.ClientCIDR)
		if err != nil {
			return nil, err
		}
		s.pool = pool
	}
	return s, nil
}

// Start binds the configured UDP port and launches the handshake
// multiplexer. It returns as soon as the socket is ready; use Accept to
// obtain connected clients.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.mux != nil {
		return errors.New("server already started")
	}

	seed, _ := parseHex32(s.cfg.SeedHex, "seed")
	psk, _ := parseHex32(s.cfg.PSKHex, "psk")
	conn, err := net.ListenPacket("udp", s.cfg.ServerAddr)
	if err != nil {
		return err
	}

	g, err := genome.GenerateWithCipher(seed, s.cfg.Generation, s.cfg.Cipher)
	if err != nil {
		conn.Close()
		return err
	}
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		conn.Close()
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	mux := tunnel.NewServerMux(conn, cp, psk)
	mux.WithKeepalive(s.cfg.KeepaliveInterval).
		WithIdleTimeout(s.cfg.IdleTimeout).
		WithRateLimit(s.cfg.RateLimitBytesPerSec).
		WithMaxSessions(s.cfg.MaxSessions)
	if !s.cfg.DisableShape {
		mux.WithShapeBuckets(compiler.DefaultShapeBuckets)
	}
	if !s.cfg.DisableDecoy {
		if dg, err := genome.GenerateWithCipher(seed, tunnel.DecoyGeneration(s.cfg.Generation), s.cfg.Cipher); err == nil {
			if dcp, err := compiler.Compile(dg, psk); err == nil {
				mux.WithDecoy(dcp)
			}
		}
	}
	done := make(chan struct{})
	go func() {
		mux.Run(ctx)
		close(done)
	}()

	s.conn = conn
	s.mux = mux
	s.cancel = cancel
	s.done = done
	return nil
}

// Accept returns the next client whose generated handshake completed.
func (s *Server) Accept(ctx context.Context) (*Conn, error) {
	s.mu.Lock()
	mux := s.mux
	pool := s.pool
	s.mu.Unlock()
	if mux == nil {
		return nil, errors.New("server not started")
	}
	t, err := mux.Accept(ctx)
	if err != nil {
		return nil, err
	}
	conn := &Conn{t: t}
	if pool != nil {
		ip, err := pool.Allocate()
		if err != nil {
			t.Close()
			return nil, err
		}
		if err := t.SendControl([]byte(ip)); err != nil {
			pool.Release(ip)
			t.Close()
			return nil, fmt.Errorf("send assigned address: %w", err)
		}
		conn.assignedIP = ip
		conn.release = func() { pool.Release(ip) }
	}
	return conn, nil
}

// LocalAddr returns the bound UDP address after Start.
func (s *Server) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	return s.conn.LocalAddr()
}

// Stats snapshots session counts and the authenticated-datagram length
// histogram (see tunnel.ServerMux.Stats). Zero value before Start.
func (s *Server) Stats() tunnel.MuxStats {
	s.mu.Lock()
	mux := s.mux
	s.mu.Unlock()
	if mux == nil {
		return tunnel.MuxStats{}
	}
	return mux.Stats()
}

// Close stops the multiplexer and closes the listening socket.
func (s *Server) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	conn := s.conn
	mux := s.mux
	done := s.done
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if mux != nil {
		mux.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
	if done != nil {
		<-done
	}
	return nil
}

// Conn is one established client session on the server.
type Conn struct {
	t          *tunnel.ServerTunnel
	assignedIP string
	release    func()
	releaseOne sync.Once
}

// SendPacket forwards one raw IP packet to this client.
func (c *Conn) SendPacket(packet []byte) error { return c.t.SendPacket(packet) }

// ReceivePacket blocks until an IP packet arrives from this client.
func (c *Conn) ReceivePacket() ([]byte, error) { return c.t.ReceivePacket() }

// AssignedIP returns the TUN address assigned by the server, if any.
func (c *Conn) AssignedIP() string { return c.assignedIP }

// Close removes this client session from the server and releases its
// assigned address.
func (c *Conn) Close() error {
	err := c.t.Close()
	c.releaseOne.Do(func() {
		if c.release != nil {
			c.release()
		}
	})
	return err
}

// RemoteAddr returns the client UDP endpoint.
func (c *Conn) RemoteAddr() net.Addr { return c.t.RemoteAddr() }

// Sum256 is a small helper for shell tools that derive seeds/PSKs.
func Sum256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
