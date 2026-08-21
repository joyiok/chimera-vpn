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
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"chimera/core"
	"chimera/internal/compiler"
	"chimera/internal/genome"
	"chimera/internal/tun"
)

// roamReapAfter is how long a same-host session must stay inbound-silent
// before a newer session from that host is allowed to reclaim it.
const roamReapAfter = 30 * time.Second

func main() {
	configPath := flag.String("config", "/etc/chimera/server.json", "server JSON config path")
	checkConfig := flag.Bool("check-config", false, "validate config and exit")
	noTun := flag.Bool("no-tun", false, "userspace packet echo (no TUN); self-test only, not a VPN")
	listen := flag.String("listen", "", "override JSON listen address (e.g. 127.0.0.1:0)")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadServerConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if *listen != "" {
		cfg.Listen = *listen
	}
	if w := configFilePermWarning(*configPath); w != "" {
		log.Printf("warning: %s", w)
	}

	coreCfg, err := toCoreConfig(cfg)
	if err != nil {
		fatal(err)
	}
	normalized, err := core.NormalizeConfig(coreCfg)
	if err != nil {
		fatal(err)
	}
	coreCfg = normalized

	if *checkConfig {
		seed, err := parseHex(coreCfg.SeedHex)
		if err != nil {
			fatal(err)
		}
		g, err := genome.GenerateWithCipher(seed, coreCfg.Generation, coreCfg.Cipher)
		if err != nil {
			fatal(fmt.Errorf("generate genome: %w", err))
		}
		fp := g.ProtocolFingerprint
		if len(fp) > 16 {
			fp = fp[:16]
		}
		fmt.Printf("config ok listen=%s transport=%s generation=%d window=%d jitter=%s sessions=%d genome=%s cover_len=%d replay=%s\n",
			coreCfg.ServerAddr, coreCfg.Transport, coreCfg.Generation, coreCfg.GenerationWindow, coreCfg.JitterMax, coreCfg.MaxSessions,
			fp, compiler.CoverLen(g), coreCfg.ReplayPath)
		return
	}

	if cfg.DisableDecoy {
		log.Printf("warning: anti-probe decoys are disabled")
	}
	if cfg.DisableShape {
		log.Printf("warning: length shaping is disabled")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, coreCfg, cfg.Tun, *noTun); err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
	}
}

func run(ctx context.Context, coreCfg core.Config, tc tunConfig, noTun bool) error {
	srv, err := core.NewServer(coreCfg)
	if err != nil {
		return err
	}
	defer srv.Close()
	if err := srv.Start(); err != nil {
		return err
	}
	log.Printf("accepting clients on %s/%s bound=%s fingerprint=%s generation=%d window=%d jitter=%s",
		coreCfg.Transport, coreCfg.ServerAddr, srv.LocalAddr(), fingerprint(coreCfg), coreCfg.Generation, coreCfg.GenerationWindow, coreCfg.JitterMax)

	if noTun {
		return runUserspace(ctx, srv)
	}
	return runTUN(ctx, srv, tc)
}

func runUserspace(ctx context.Context, srv *core.Server) error {
	log.Printf("warning: -no-tun userspace echo is for self-test only; packets are reflected, not routed")
	fatalCh := make(chan error, 1)
	go acceptLoop(ctx, srv, fatalCh, nil, true)
	go statsLoop(ctx, srv)
	go watchUSR1(ctx, func() { dumpStats(srv, nil) })
	return waitRun(ctx, fatalCh)
}

func runTUN(ctx context.Context, srv *core.Server, tc tunConfig) error {
	dev, err := tun.Open(tc.Name)
	if err != nil {
		return fmt.Errorf("open TUN: %w (run as root or grant CAP_NET_ADMIN, or pass -no-tun to self-test)", err)
	}
	defer dev.Close()
	log.Printf("TUN interface %s opened", dev.Name())

	if err := configureTUN(dev.Name(), tc.Address, tc.MTU); err != nil {
		return err
	}
	log.Printf("address %s, MTU %d", tc.Address, tc.MTU)

	routes := newClientRoute()
	fatalCh := make(chan error, 1)

	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, err := dev.Read(buf)
			if err != nil {
				select {
				case fatalCh <- fmt.Errorf("tun read: %w", err):
				default:
				}
				return
			}
			dst := packetIP(buf[:n], true)
			conn := routes.lookup(dst)
			if conn == nil {
				continue
			}
			if err := conn.SendPacket(buf[:n]); err != nil {
				log.Printf("drop packet to %s: %v", dst, err)
				continue
			}
		}
	}()

	go acceptLoop(ctx, srv, fatalCh, &tunAccept{dev: dev, routes: routes}, false)
	go statsLoop(ctx, srv)
	go watchUSR1(ctx, func() { dumpStats(srv, routes) })
	return waitRun(ctx, fatalCh)
}

type tunAccept struct {
	dev    *tun.Device
	routes *clientRoute
}

func acceptLoop(ctx context.Context, srv *core.Server, fatalCh chan error, tun *tunAccept, echo bool) {
	for {
		conn, err := srv.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				select {
				case fatalCh <- fmt.Errorf("accept: %w", err):
				default:
				}
			}
			return
		}
		log.Printf("client %s connected generation=%d", conn.RemoteAddr(), conn.Generation())
		if echo {
			go pumpEcho(conn)
			continue
		}
		go pumpClientToTun(conn, tun.dev, tun.routes)
	}
}

func statsLoop(ctx context.Context, srv *core.Server) {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dumpStats(srv, nil)
		}
	}
}

func dumpStats(srv *core.Server, routes *clientRoute) {
	st := srv.Stats()
	log.Printf("stats: sessions=%d pending=%d decoys=%d frame_lens=%s",
		st.Established, st.Pending, st.Decoys, formatFrameLens(st.FrameLens))
	if routes == nil {
		return
	}
	for _, s := range routes.snapshot() {
		log.Print(formatSessionSnap(s))
	}
}

func waitRun(ctx context.Context, fatalCh <-chan error) error {
	select {
	case err := <-fatalCh:
		if ctx.Err() != nil {
			return nil
		}
		return err
	case <-ctx.Done():
		log.Println("shutting down")
		return nil
	}
}

func pumpEcho(conn *core.Conn) {
	defer conn.Close()
	if ip := conn.AssignedIP(); ip != "" {
		log.Printf("client %s assigned TUN address %s (echo)", conn.RemoteAddr(), ip)
	}
	for {
		pkt, err := conn.ReceivePacket()
		if err != nil {
			log.Printf("client %s disconnected: %v", conn.RemoteAddr(), err)
			return
		}
		if err := conn.SendPacket(pkt); err != nil {
			log.Printf("echo to %s: %v", conn.RemoteAddr(), err)
			return
		}
	}
}

func pumpClientToTun(conn *core.Conn, dev *tun.Device, routes *clientRoute) {
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
				log.Printf("client %s disconnected: %v", conn.RemoteAddr(), err)
			}
			return
		}
		src := packetIP(pkt, false)
		if src != "" {
			if displaced := routes.register(conn, src); displaced != nil && displaced != conn {
				log.Printf("WARNING: %s re-registered TUN address %s previously used by %s; closing displaced session",
					conn.RemoteAddr(), src, displaced.RemoteAddr())
				// Two live writers for one source IP would ping-pong packets
				// into the TUN and hold a pool lease + session slot until
				// the idle reap. Close the displaced session eagerly.
				_ = displaced.Close()
			}
			registered = true
			// Roam reclamation: a client that rebound its NAT port leaves
			// its old session silent on an old endpoint. Reap it early so
			// it does not pin a pool address / MaxSessions slot.
			for _, old := range routes.reapRoamed(hostIP(conn.RemoteAddr()), conn, roamReapAfter) {
				log.Printf("closing roamed session from %s (silent >= %v)", old.RemoteAddr(), roamReapAfter)
				_ = old.Close()
			}
		}
		if _, err := dev.Write(pkt); err != nil {
			log.Printf("tun write from %s: %v", conn.RemoteAddr(), err)
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
