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
}

// NewClient prepares a client; Start establishes the tunnel.
func NewClient(cfg Config) (*Client, error) {
	cfg, err := NormalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg}, nil
}

// Start runs the generated UDP handshake with the configured server.
func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.tun != nil {
		return errors.New("client already started")
	}

	seed, _ := parseHex32(c.cfg.SeedHex, "seed")
	psk, _ := parseHex32(c.cfg.PSKHex, "psk")
	remote, err := net.ResolveUDPAddr("udp", c.cfg.ServerAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return err
	}

	g, err := genome.Generate(seed, c.cfg.Generation)
	if err != nil {
		conn.Close()
		return err
	}
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		conn.Close()
		return err
	}
	h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		conn.Close()
		return err
	}
	sess, err := tunnel.ClientHandshake(conn, remote, h)
	if err != nil {
		conn.Close()
		return err
	}

	c.conn = conn
	c.tun = tunnel.NewPacketTunnel(conn, remote, sess)
	return nil
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

	g, err := genome.Generate(seed, s.cfg.Generation)
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
