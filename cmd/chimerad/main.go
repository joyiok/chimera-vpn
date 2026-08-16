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

func main() {
	configPath := flag.String("config", "/etc/chimera/server.json", "server JSON config path")
	checkConfig := flag.Bool("check-config", false, "validate config and exit")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadServerConfig(*configPath)
	if err != nil {
		fatal(err)
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
		fmt.Printf("config ok listen=%s generation=%d window=%d jitter=%s sessions=%d genome=%s cover_len=%d replay=%s\n",
			coreCfg.ServerAddr, coreCfg.Generation, coreCfg.GenerationWindow, coreCfg.JitterMax, coreCfg.MaxSessions,
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

	if err := run(ctx, coreCfg, cfg.Tun); err != nil && !errors.Is(err, context.Canceled) {
		fatal(err)
	}
}

func run(ctx context.Context, coreCfg core.Config, tc tunConfig) error {
	dev, err := tun.Open(tc.Name)
	if err != nil {
		return fmt.Errorf("open TUN: %w (run as root or grant CAP_NET_ADMIN)", err)
	}
	defer dev.Close()
	log.Printf("TUN interface %s opened", dev.Name())

	if err := configureTUN(dev.Name(), tc.Address, tc.MTU); err != nil {
		return err
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
	log.Printf("accepting clients on udp/%s fingerprint=%s generation=%d window=%d jitter=%s",
		coreCfg.ServerAddr, fingerprint(coreCfg), coreCfg.Generation, coreCfg.GenerationWindow, coreCfg.JitterMax)

	routes := newClientRoute()
	fatalCh := make(chan error, 1)

	// TUN -> right client, selected by destination IP.
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
				continue // packet for an unknown client; drop silently
			}
			if err := conn.SendPacket(buf[:n]); err != nil {
				log.Printf("drop packet to %s: %v", dst, err)
				continue
			}
		}
	}()

	// Accept loop: one client pump per established session.
	go func() {
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
			go pumpClientToTun(conn, dev, routes)
		}
	}()

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
				log.Printf("WARNING: %s re-registered TUN address %s previously used by %s",
					conn.RemoteAddr(), src, displaced.RemoteAddr())
			}
			registered = true
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
