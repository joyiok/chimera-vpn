// Package core is the cross-platform CHIMERA client/server API. Windows and
// Android shells call into this package (or into bind, which wraps it for
// gomobile).
package core

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
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
	// Transport selects the underlay: "udp" (default) or "tcp".
	// TCP wraps the same generated-protocol datagrams in 2-byte length
	// frames for networks where UDP is QoS-throttled.
	Transport string
	// StreamDecoyMode controls unauthenticated first frames on TCP
	// listeners: "close", "silent" (default), or "tls". See
	// tunnel.StreamProbeMode.
	StreamDecoyMode tunnel.StreamProbeMode
	// StreamDecoyTimeout bounds one silent decoy connection. <= 0 uses
	// tunnel.DefaultStreamProbeTimeout.
	StreamDecoyTimeout time.Duration
	// StreamDecoyMaxPending caps concurrent unauthenticated TCP conns.
	// <= 0 uses tunnel.DefaultStreamProbeMaxPending.
	StreamDecoyMaxPending int
	// DecoyEvery emits one high-entropy noise frame every N real writes
	// on authenticated sessions. 0 uses 48; negative disables.
	DecoyEvery int
	// DecoyMaxPerSec caps noise frames per second. 0 uses 2; negative
	// disables decoys together with DecoyEvery.
	DecoyMaxPerSec int
	// PortHopCount derives additional server ports from seed+generation.
	// 0/1 disables hopping. Clients probe the same sequence in order.
	PortHopCount int
	// PortHopSpread bounds the derived port offset from the base port.
	// <= 0 uses 2048.
	PortHopSpread int
	// TLSCertFile / TLSKeyFile enable wss on the server.
	TLSCertFile string
	TLSKeyFile  string
	// TLSCAFile adds a custom root CA on clients; empty uses system roots.
	TLSCAFile string
	// TLSInsecureSkipVerify is for development only and must never be
	// enabled in production profiles.
	TLSInsecureSkipVerify bool
	ClientCIDR            string // server-only: client TUN pool, e.g. 10.99.0.0/24
	// Cipher overrides the genome's cipher draw ("" = genome default).
	// genome.CipherChaCha20P1305 suits clients without AES acceleration;
	// both endpoints must configure the same value.
	Cipher string
	// KeepaliveInterval refreshes NAT mappings on idle links (< 0 disables,
	// 0 uses tunnel.DefaultKeepaliveInterval).
	KeepaliveInterval time.Duration
	// GenerationWindow: clients probe this many successive generations
	// after a handshake timeout. Servers accept Generation through
	// Generation+Window in parallel (client-first genotypes; server-first
	// knocks still bind to the base generation). 0 means only the
	// configured generation.
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
	// JitterMax smears send timing with a truncated exponential in
	// (0, JitterMax]. 0 disables jitter. Production servers should use
	// tunnel.DefaultJitterMax.
	JitterMax time.Duration
	// ReplayPath (server) persists authenticated handshake/knock hashes
	// across process restarts. Empty keeps the table in memory only.
	ReplayPath string
}

// MaxGenerationWindow caps how many extra generations a server will accept
// (or a client will probe). Larger windows cost CPU on every probe packet.
const MaxGenerationWindow = 8

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
	cfg.Transport = strings.ToLower(strings.TrimSpace(cfg.Transport))
	if cfg.Transport == "" {
		cfg.Transport = "udp"
	}
	if cfg.Transport != "udp" && cfg.Transport != "tcp" && cfg.Transport != "websocket" && cfg.Transport != "wss" && cfg.Transport != "http" && cfg.Transport != "https" {
		return cfg, fmt.Errorf("unknown transport %q (want udp, tcp, websocket, wss, http, or https)", cfg.Transport)
	}
	cfg.StreamDecoyMode, err = tunnel.NormalizeStreamProbeMode(cfg.StreamDecoyMode)
	if err != nil {
		return cfg, err
	}
	if cfg.StreamDecoyTimeout <= 0 {
		cfg.StreamDecoyTimeout = tunnel.DefaultStreamProbeTimeout
	}
	if cfg.StreamDecoyMaxPending <= 0 {
		cfg.StreamDecoyMaxPending = tunnel.DefaultStreamProbeMaxPending
	}
	if cfg.DecoyEvery == 0 {
		cfg.DecoyEvery = 48
	}
	if cfg.DecoyMaxPerSec == 0 {
		cfg.DecoyMaxPerSec = 2
	}
	if cfg.DecoyEvery < 0 || cfg.DecoyMaxPerSec < 0 {
		cfg.DecoyEvery = 0
		cfg.DecoyMaxPerSec = 0
	}
	if cfg.PortHopCount < 0 {
		return cfg, fmt.Errorf("port hop count must be >= 0")
	}
	if cfg.PortHopCount == 0 {
		cfg.PortHopCount = 1
	}
	if cfg.PortHopCount > 16 {
		return cfg, fmt.Errorf("port hop count %d exceeds max 16", cfg.PortHopCount)
	}
	if cfg.PortHopCount > 1 && cfg.PortHopSpread <= 0 {
		cfg.PortHopSpread = 2048
	}
	if cfg.Cipher != "" && !genome.KnownCipher(cfg.Cipher) {
		return cfg, fmt.Errorf("unknown cipher %q", cfg.Cipher)
	}
	if cfg.GenerationWindow > MaxGenerationWindow {
		return cfg, fmt.Errorf("generation window %d exceeds max %d", cfg.GenerationWindow, MaxGenerationWindow)
	}
	if cfg.JitterMax < 0 {
		cfg.JitterMax = 0
	}
	if cfg.JitterMax > tunnel.MaxJitterMax {
		return cfg, fmt.Errorf("jitter %s exceeds max %s", cfg.JitterMax, tunnel.MaxJitterMax)
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

// startSession performs one full dial across the port-hop sequence: socket,
// genome, handshake. Dead derived ports are skipped quickly; the first
// working port becomes the session endpoint.
func startSession(cfg Config, generation uint64) (*tunnel.PacketTunnel, net.PacketConn, error) {
	addrs, err := hopAddrsForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	timeout := time.Duration(0) // single port: keep the standard 8s handshake timeout
	if len(addrs) > 1 {
		timeout = tunnel.PortHopHandshakeTimeout
	}
	var lastErr error
	for _, addr := range addrs {
		attemptCfg := cfg
		attemptCfg.ServerAddr = addr
		tun, conn, err := dialSession(attemptCfg, generation, timeout)
		if err == nil {
			return tun, conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = tunnel.ErrHandshakeTimeout
	}
	return nil, nil, lastErr
}

func dialSession(cfg Config, generation uint64, handshakeTimeout time.Duration) (*tunnel.PacketTunnel, net.PacketConn, error) {
	seed, _ := parseHex32(cfg.SeedHex, "seed")
	psk, _ := parseHex32(cfg.PSKHex, "psk")

	if cfg.Transport == "tcp" || cfg.Transport == "websocket" || cfg.Transport == "wss" || cfg.Transport == "http" || cfg.Transport == "https" {
		var conn net.PacketConn
		var peer net.Addr
		var err error
		switch cfg.Transport {
		case "websocket":
			conn, peer, err = tunnel.DialWebSocketPacket(context.Background(), cfg.ServerAddr, websocketPath(cfg.SeedHex, cfg.Generation))
		case "wss":
			var tlsCfg *tls.Config
			tlsCfg, err = clientTLSConfig(cfg)
			if err == nil {
				conn, peer, err = tunnel.DialWebSocketPacketTLS(context.Background(), cfg.ServerAddr, websocketPath(cfg.SeedHex, cfg.Generation), tlsCfg)
			}
		case "http":
			base := "http://" + cfg.ServerAddr + websocketPath(cfg.SeedHex, cfg.Generation)
			raw, rAddr, dErr := tunnel.DialHTTPStream(context.Background(), base, nil)
			if dErr == nil {
				conn, peer, err = tunnel.NewStreamPacketConn(raw), rAddr, nil
			} else {
				err = dErr
			}
		case "https":
			var tlsCfg *tls.Config
			tlsCfg, err = clientTLSConfig(cfg)
			if err == nil {
				base := "https://" + cfg.ServerAddr + websocketPath(cfg.SeedHex, cfg.Generation)
				raw, rAddr, dErr := tunnel.DialHTTPStream(context.Background(), base, tlsCfg)
				if dErr == nil {
					conn, peer, err = tunnel.NewStreamPacketConn(raw), rAddr, nil
				} else {
					err = dErr
				}
			}
		default:
			conn, peer, err = tunnel.DialStream(context.Background(), cfg.ServerAddr)
		}
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
		sess, err := tunnel.ClientHandshakeWithJitterTimeout(conn, peer, h, cfg.JitterMax, handshakeTimeout)
		if err != nil {
			conn.Close()
			return nil, nil, err
		}
		t := tunnel.NewPacketTunnel(conn, peer, sess)
		configureTunnel(t, cfg, compiler.ShapeBucketsForGenome(g))
		return t, conn, nil
	}

	remote, err := net.ResolveUDPAddr("udp", cfg.ServerAddr)
	if err != nil {
		return nil, nil, err
	}
	conn, err := tunnel.ListenUDP(context.Background(), ":0")
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
	sess, err := tunnel.ClientHandshakeWithJitterTimeout(conn, remote, h, cfg.JitterMax, handshakeTimeout)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	t := tunnel.NewPacketTunnel(conn, remote, sess)
	configureTunnel(t, cfg, compiler.ShapeBucketsForGenome(g))
	return t, conn, nil
}

// configureTunnel applies the shared traffic-shaping settings for both UDP
// and TCP sessions.
func configureTunnel(t *tunnel.PacketTunnel, cfg Config, shapeBuckets []int) {
	if !cfg.DisableShape && len(shapeBuckets) > 0 {
		t.SetShapeBuckets(shapeBuckets)
	}
	t.SetJitter(cfg.JitterMax)
	t.SetKeepalive(cfg.KeepaliveInterval)
	t.SetTxMask(tunnel.NewNoiseTxMask(cfg.DecoyEvery, cfg.DecoyMaxPerSec, shapeBuckets))
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

// IdleFor is inbound silence (time since the last authenticated frame from
// the peer). Own keepalives do not reset it. A healthy link stays well
// below one server keepalive interval; several multiples indicate loss.
// Returns 0 when not started.
func (c *Client) IdleFor() time.Duration {
	c.mu.Lock()
	t := c.tun
	c.mu.Unlock()
	if t == nil {
		return 0
	}
	return t.IdleFor()
}

// Bytes is TUN payload volume since Start (IP packets only).
func (c *Client) Bytes() (sent, recv uint64) {
	c.mu.Lock()
	t := c.tun
	c.mu.Unlock()
	if t == nil {
		return 0, 0
	}
	return t.Bytes()
}

// serverSession is the common interface implemented by both a UDP-mux
// ServerTunnel and a dedicated TCP-stream PacketTunnel.
type serverSession interface {
	SendPacket(packet []byte) error
	ReceivePacket() ([]byte, error)
	SendControl(payload []byte) error
	RemoteAddr() net.Addr
	IdleFor() time.Duration
	Close() error
}

// streamAccept is a completed TCP handshake waiting for Server.Accept.
type streamAccept struct {
	t          *tunnel.PacketTunnel
	generation uint64
}

// Server multiplexes many generated-protocol clients over one UDP socket
// (transport=udp) or accepts one TCP stream per client (transport=tcp).
type Server struct {
	cfg Config

	mu          sync.Mutex
	conn        net.PacketConn // first UDP socket (kept for LocalAddr compat)
	conns       []net.PacketConn
	mux         *tunnel.ServerMux // first UDP mux (kept for stats compat)
	muxes       []*tunnel.ServerMux
	muxAcceptCh chan *tunnel.ServerTunnel
	tcpLns      []net.Listener
	wsLns       []net.Listener
	wsSrvs      []*http.Server
	wsDone      chan struct{}
	httpLns     []net.Listener
	httpSrvs    []*http.Server
	httpDone    chan struct{}
	httpPairs   map[string]*httpSession
	tcpAcceptCh chan streamAccept
	tcpDone     chan struct{}
	tcpSessions map[*tunnel.PacketTunnel]struct{}
	tcpDecoys   atomic.Int64
	tcpPending  atomic.Int64
	cancel      context.CancelFunc
	done        chan struct{}
	pool        *addressPool
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

// compileServerProtocols builds the accepted generation window. The first
// compiled protocol is the base generation.
func compileServerProtocols(cfg Config) ([]*compiler.CompiledProtocol, []byte, error) {
	seed, err := parseHex32(cfg.SeedHex, "seed")
	if err != nil {
		return nil, nil, err
	}
	psk, err := parseHex32(cfg.PSKHex, "psk")
	if err != nil {
		return nil, nil, err
	}
	cps := make([]*compiler.CompiledProtocol, 0, cfg.GenerationWindow+1)
	for i := uint64(0); i <= cfg.GenerationWindow; i++ {
		g, err := genome.GenerateWithCipher(seed, cfg.Generation+i, cfg.Cipher)
		if err != nil {
			return nil, nil, err
		}
		cp, err := compiler.Compile(g, psk)
		if err != nil {
			return nil, nil, err
		}
		cps = append(cps, cp)
	}
	return cps, psk, nil
}

// Start binds every derived port and launches handshake processing. It
// returns as soon as the first socket is ready; use Accept to obtain
// connected clients.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.muxes) != 0 || len(s.tcpLns) != 0 {
		return errors.New("server already started")
	}

	ports, err := hopPortsForConfig(s.cfg)
	if err != nil {
		return err
	}
	addrs, err := listenAddrsForPorts(s.cfg, ports)
	if err != nil {
		return err
	}
	cps, psk, err := compileServerProtocols(s.cfg)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	if s.cfg.Transport == "tcp" {
		return s.startTCPListeners(ctx, addrs, cps, psk)
	}
	if s.cfg.Transport == "websocket" || s.cfg.Transport == "wss" {
		return s.startWebSocketListeners(ctx, addrs, cps, psk)
	}
	if s.cfg.Transport == "http" || s.cfg.Transport == "https" {
		return s.startHTTPListeners(ctx, addrs, cps, psk)
	}
	return s.startUDPMuxes(ctx, addrs, cps, psk)
}

func (s *Server) newMux(conn net.PacketConn, cps []*compiler.CompiledProtocol, psk []byte) *tunnel.ServerMux {
	mux := tunnel.NewServerMux(conn, cps[0], psk)
	mux.WithProtocols(cps).
		WithKeepalive(s.cfg.KeepaliveInterval).
		WithIdleTimeout(s.cfg.IdleTimeout).
		WithRateLimit(s.cfg.RateLimitBytesPerSec).
		WithMaxSessions(s.cfg.MaxSessions).
		WithJitter(s.cfg.JitterMax)
	var txShapeBuckets []int
	if !s.cfg.DisableShape {
		txShapeBuckets = compiler.ShapeBucketsForGenome(cps[0].Genome)
		mux.WithShapeBuckets(txShapeBuckets)
	}
	mux.WithTxMask(tunnel.NewNoiseTxMask(s.cfg.DecoyEvery, s.cfg.DecoyMaxPerSec, txShapeBuckets))
	if !s.cfg.DisableDecoy {
		seed, _ := parseHex32(s.cfg.SeedHex, "seed")
		if dg, err := genome.GenerateWithCipher(seed, tunnel.DecoyGeneration(s.cfg.Generation), s.cfg.Cipher); err == nil {
			if dcp, err := compiler.Compile(dg, psk); err == nil {
				mux.WithDecoy(dcp)
			}
		}
	}
	mux.WithReplayPath(s.cfg.ReplayPath)
	return mux
}

func (s *Server) startUDPMuxes(ctx context.Context, addrs []string, cps []*compiler.CompiledProtocol, psk []byte) error {
	s.muxAcceptCh = make(chan *tunnel.ServerTunnel, 32)
	s.done = make(chan struct{})
	var wg sync.WaitGroup
	for _, addr := range addrs {
		conn, err := tunnel.ListenUDP(context.Background(), addr)
		if err != nil {
			_ = ctx.Err()
			s.cancel()
			for _, c := range s.conns {
				_ = c.Close()
			}
			return fmt.Errorf("listen udp %s: %w", addr, err)
		}
		mux := s.newMux(conn, cps, psk)
		s.conns = append(s.conns, conn)
		s.muxes = append(s.muxes, mux)

		wg.Add(2)
		go func(mux *tunnel.ServerMux) {
			defer wg.Done()
			mux.Run(ctx)
		}(mux)
		go func(mux *tunnel.ServerMux) {
			defer wg.Done()
			for {
				tun, err := mux.Accept(ctx)
				if err != nil {
					return
				}
				select {
				case s.muxAcceptCh <- tun:
				case <-ctx.Done():
					_ = tun.Close()
					return
				}
			}
		}(mux)
	}
	go func() {
		wg.Wait()
		close(s.done)
	}()
	s.conn = s.conns[0]
	s.mux = s.muxes[0]
	return nil
}

func (s *Server) startTCPListeners(ctx context.Context, addrs []string, cps []*compiler.CompiledProtocol, psk []byte) error {
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range s.tcpLns {
				_ = l.Close()
			}
			s.cancel()
			return fmt.Errorf("listen tcp %s: %w", addr, err)
		}
		s.tcpLns = append(s.tcpLns, ln)
	}
	s.tcpAcceptCh = make(chan streamAccept, max(16, len(addrs)*16))
	s.tcpDone = make(chan struct{})
	s.tcpSessions = make(map[*tunnel.PacketTunnel]struct{})
	var wg sync.WaitGroup
	for _, ln := range s.tcpLns {
		wg.Add(1)
		go func(ln net.Listener) {
			defer wg.Done()
			s.runTCPAccept(ctx, ln, cps, psk)
		}(ln)
	}
	go func() {
		wg.Wait()
		close(s.tcpDone)
	}()
	return nil
}

func (s *Server) startWebSocketListeners(ctx context.Context, addrs []string, cps []*compiler.CompiledProtocol, psk []byte) error {
	path := websocketPath(s.cfg.SeedHex, s.cfg.Generation)
	var tlsCfg *tls.Config
	if s.cfg.Transport == "wss" {
		var err error
		tlsCfg, err = serverTLSConfig(s.cfg)
		if err != nil {
			return err
		}
	}
	for _, addr := range addrs {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			for _, l := range s.wsLns {
				_ = l.Close()
			}
			s.cancel()
			return fmt.Errorf("listen websocket %s: %w", addr, err)
		}
		serveLn := net.Listener(ln)
		if tlsCfg != nil {
			serveLn = tls.NewListener(serveLn, tlsCfg)
		}
		srv := &http.Server{
			Handler:           s.wsHandler(path, cps, psk),
			ReadHeaderTimeout: 5 * time.Second,
		}
		s.wsLns = append(s.wsLns, ln)
		s.wsSrvs = append(s.wsSrvs, srv)
		go func(srv *http.Server, serveLn net.Listener) {
			_ = srv.Serve(serveLn)
		}(srv, serveLn)
	}
	s.tcpAcceptCh = make(chan streamAccept, max(16, len(addrs)*16))
	s.tcpSessions = make(map[*tunnel.PacketTunnel]struct{})
	s.wsDone = make(chan struct{})
	go func() {
		<-ctx.Done()
		for _, srv := range s.wsSrvs {
			_ = srv.Close()
		}
	}()
	return nil
}

// wsHandler serves the hidden WebSocket upgrade path. Every other path gets
// a tiny generic 404 page, so the listener looks like an ordinary HTTP
// server to scanners that cannot guess the seed-derived path.
func (s *Server) wsHandler(path string, cps []*compiler.CompiledProtocol, psk []byte) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte("not found\n"))
			return
		}
		conn, err := tunnel.UpgradeWebSocket(w, r)
		if err != nil {
			return
		}
		s.handleStreamConn(r.Context(), conn, cps, psk)
	})
}

// runTCPAccept accepts TCP streams, runs one generated handshake per
// connection, and queues established tunnels for Server.Accept.
func (s *Server) runTCPAccept(ctx context.Context, ln net.Listener, cps []*compiler.CompiledProtocol, psk []byte) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		if s.cfg.MaxSessions > 0 && s.tcpPending.Load() >= int64(s.cfg.MaxSessions) {
			_ = conn.Close()
			continue
		}
		s.tcpPending.Add(1)
		go func(conn net.Conn) {
			defer s.tcpPending.Add(-1)
			s.handleStreamConn(ctx, conn, cps, psk)
		}(conn)
	}
}

func (s *Server) handleStreamConn(ctx context.Context, conn net.Conn, cps []*compiler.CompiledProtocol, psk []byte) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetNoDelay(true)
		_ = tc.SetKeepAlive(true)
		_ = tc.SetKeepAlivePeriod(tunnel.DefaultKeepaliveInterval)
	}
	t, generation, err := tunnel.ServerHandshakeStream(conn, cps, psk, s.cfg.JitterMax)
	if err != nil {
		var probe *tunnel.StreamProbeError
		if errors.As(err, &probe) {
			s.handleStreamProbe(conn, probe.First)
		} else {
			_ = conn.Close()
		}
		return
	}
	buckets := compiler.DefaultShapeBuckets
	if !s.cfg.DisableShape {
		if int(generation) < len(cps) {
			buckets = compiler.ShapeBucketsForGenome(cps[generation].Genome)
		}
		t.SetShapeBuckets(buckets)
	}
	t.SetJitter(s.cfg.JitterMax)
	t.SetKeepalive(s.cfg.KeepaliveInterval)
	t.SetTxMask(tunnel.NewNoiseTxMask(s.cfg.DecoyEvery, s.cfg.DecoyMaxPerSec, buckets))

	s.mu.Lock()
	if s.tcpSessions == nil {
		s.tcpSessions = make(map[*tunnel.PacketTunnel]struct{})
	}
	s.tcpSessions[t] = struct{}{}
	s.mu.Unlock()

	select {
	case s.tcpAcceptCh <- streamAccept{t: t, generation: generation}:
	case <-ctx.Done():
		s.unregisterStream(t)
		_ = t.Close()
	}
}

func (s *Server) unregisterStream(t *tunnel.PacketTunnel) {
	s.mu.Lock()
	delete(s.tcpSessions, t)
	s.mu.Unlock()
}

// Accept returns the next client whose generated handshake completed.
func (s *Server) Accept(ctx context.Context) (*Conn, error) {
	s.mu.Lock()
	if s.cfg.Transport == "tcp" || s.cfg.Transport == "websocket" || s.cfg.Transport == "wss" || s.cfg.Transport == "http" || s.cfg.Transport == "https" {
		ch := s.tcpAcceptCh
		s.mu.Unlock()
		if ch == nil {
			return nil, errors.New("server not started")
		}
		select {
		case a := <-ch:
			return s.makeConn(a.t, a.generation)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	ch := s.muxAcceptCh
	s.mu.Unlock()
	if ch == nil {
		return nil, errors.New("server not started")
	}
	select {
	case t := <-ch:
		return s.makeConn(t, t.Generation())
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// makeConn allocates an address when configured and wraps a session as a
// public Conn. TCP sessions are registered for Close cleanup and reap
// themselves when idle past the configured timeout.
func (s *Server) makeConn(t serverSession, generation uint64) (*Conn, error) {
	conn := &Conn{t: t, generation: generation, done: make(chan struct{})}
	if s.pool != nil {
		ip, err := s.pool.Allocate()
		if err != nil {
			_ = t.Close()
			return nil, err
		}
		if err := t.SendControl([]byte(ip)); err != nil {
			s.pool.Release(ip)
			_ = t.Close()
			return nil, fmt.Errorf("send assigned address: %w", err)
		}
		conn.assignedIP = ip
		conn.release = func() { s.pool.Release(ip) }
	}
	if s.cfg.Transport == "tcp" {
		pt, ok := t.(*tunnel.PacketTunnel)
		if ok {
			conn.onClose = func() { s.unregisterStream(pt) }
		}
		if s.cfg.IdleTimeout > 0 {
			go conn.reapIdle(s.cfg.IdleTimeout)
		}
	}
	return conn, nil
}

// LocalAddr returns the bound UDP or TCP address after Start.
func (s *Server) LocalAddr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	if len(s.tcpLns) > 0 {
		return s.tcpLns[0].Addr()
	}
	if len(s.wsLns) > 0 {
		return s.wsLns[0].Addr()
	}
	if len(s.httpLns) > 0 {
		return s.httpLns[0].Addr()
	}
	return nil
}

// Stats snapshots session counts and the authenticated-datagram length
// histogram across every bound port (see tunnel.ServerMux.Stats). Zero
// value before Start.
func (s *Server) Stats() tunnel.MuxStats {
	s.mu.Lock()
	muxes := append([]*tunnel.ServerMux(nil), s.muxes...)
	s.mu.Unlock()
	if len(muxes) == 0 {
		return tunnel.MuxStats{}
	}
	first := muxes[0].Stats()
	out := tunnel.MuxStats{FrameLens: make([]uint64, len(first.FrameLens))}
	for _, mux := range muxes {
		st := mux.Stats()
		out.Established += st.Established
		out.Pending += st.Pending
		out.Decoys += st.Decoys
		for i := range st.FrameLens {
			out.FrameLens[i] += st.FrameLens[i]
		}
	}
	return out
}

// Close stops every listener/mux and closes every session socket.
func (s *Server) Close() error {
	s.mu.Lock()
	cancel := s.cancel
	conns := append([]net.PacketConn(nil), s.conns...)
	muxes := append([]*tunnel.ServerMux(nil), s.muxes...)
	done := s.done
	tcpLns := append([]net.Listener(nil), s.tcpLns...)
	wsSrvs := append([]*http.Server(nil), s.wsSrvs...)
	wsLns := append([]net.Listener(nil), s.wsLns...)
	wsDone := s.wsDone
	httpSrvs := append([]*http.Server(nil), s.httpSrvs...)
	httpLns := append([]net.Listener(nil), s.httpLns...)
	httpDone := s.httpDone
	httpPairs := s.httpPairs
	s.httpPairs = make(map[string]*httpSession)
	tcpDone := s.tcpDone
	tcpSessions := make([]*tunnel.PacketTunnel, 0, len(s.tcpSessions))
	for t := range s.tcpSessions {
		tcpSessions = append(tcpSessions, t)
	}
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	for _, mux := range muxes {
		mux.Close()
	}
	for _, conn := range conns {
		_ = conn.Close()
	}
	for _, ln := range tcpLns {
		_ = ln.Close()
	}
	wsCtx, wsCancel := context.WithTimeout(context.Background(), 2*time.Second)
	for _, srv := range wsSrvs {
		_ = srv.Shutdown(wsCtx)
	}
	wsCancel()
	for _, ln := range wsLns {
		_ = ln.Close()
	}
	httpCtx, httpCancel := context.WithTimeout(context.Background(), 2*time.Second)
	for _, srv := range httpSrvs {
		_ = srv.Shutdown(httpCtx)
	}
	httpCancel()
	for _, ln := range httpLns {
		_ = ln.Close()
	}
	for _, p := range httpPairs {
		p.mu.Lock()
		if !p.started && p.down == nil && p.up == nil {
			p.started = true
			close(p.done)
		}
		p.mu.Unlock()
	}
	for _, t := range tcpSessions {
		_ = t.Close()
	}
	if tcpDone != nil {
		<-tcpDone
	}
	if wsDone != nil {
		select {
		case <-wsDone:
		case <-time.After(2 * time.Second):
		}
	}
	if httpDone != nil {
		select {
		case <-httpDone:
		case <-time.After(2 * time.Second):
		}
	}
	if done != nil {
		<-done
	}
	return nil
}

// Conn is one established client session on the server.
type Conn struct {
	t          serverSession
	assignedIP string
	generation uint64
	release    func()
	onClose    func()
	done       chan struct{}
	closeOnce  sync.Once
}

// SendPacket forwards one raw IP packet to this client.
func (c *Conn) SendPacket(packet []byte) error { return c.t.SendPacket(packet) }

// ReceivePacket blocks until an IP packet arrives from this client.
func (c *Conn) ReceivePacket() ([]byte, error) { return c.t.ReceivePacket() }

// AssignedIP returns the TUN address assigned by the server, if any.
func (c *Conn) AssignedIP() string { return c.assignedIP }

// Generation is the genome generation this client matched.
func (c *Conn) Generation() uint64 { return c.generation }

// Close removes this client session from the server and releases its
// assigned address. Safe to call more than once.
func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		close(c.done)
		if c.release != nil {
			c.release()
		}
		if c.onClose != nil {
			c.onClose()
		}
	})
	return c.t.Close()
}

// reapIdle closes a TCP session after too much inbound silence. UDP
// sessions are reaped by ServerMux and do not use this path.
func (c *Conn) reapIdle(timeout time.Duration) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			if c.IdleFor() >= timeout {
				_ = c.Close()
				return
			}
		}
	}
}

// RemoteAddr returns the client UDP endpoint.
func (c *Conn) RemoteAddr() net.Addr {
	if c == nil || c.t == nil {
		return nil
	}
	return c.t.RemoteAddr()
}

// IdleFor is inbound silence on this session (own keepalives do not count).
func (c *Conn) IdleFor() time.Duration {
	if c == nil || c.t == nil {
		return 0
	}
	return c.t.IdleFor()
}

// Sum256 is a small helper for shell tools that derive seeds/PSKs.
func Sum256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
