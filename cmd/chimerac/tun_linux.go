//go:build linux

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"chimera/core"
	"chimera/internal/tun"
)

func runVPN(cfg clientConfig, opt vpnOptions) error {
	takeRoute := opt.takeRoute || cfg.TakeDefaultRoute
	lostAfter := opt.lostAfter
	if lostAfter < 0 {
		lostAfter = 0
	}

	sigCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	client, assigned, err := startClient(cfg, 10*time.Second)
	if err != nil {
		return err
	}
	log.Printf("handshake ok generation=%d assigned=%s", client.Generation(), assigned)

	dev, err := tun.Open(cfg.TunName)
	if err != nil {
		_ = client.Close()
		return fmt.Errorf("open TUN: %w (run as root or grant CAP_NET_ADMIN)", err)
	}
	defer dev.Close()

	if err := configureClientTUN(dev.Name(), assigned+"/24", cfg.MTU); err != nil {
		_ = client.Close()
		return err
	}
	log.Printf("TUN %s %s/24 mtu=%d", dev.Name(), assigned, cfg.MTU)

	var routes *linuxRoutes
	if takeRoute {
		if err := configureClientTUN6(dev.Name(), clientTUN6); err != nil {
			log.Printf("IPv6 TUN address skipped: %v", err)
		}
		routes, err = installDefaultRoutes(dev.Name(), assigned, cfg.ServerAddr)
		if err != nil {
			log.Printf("default-route takeover failed (tunnel still up): %v", err)
		} else {
			log.Printf("default route taken over via %s (server /32 exception for %s)", dev.Name(), cfg.ServerAddr)
			dns := pushTUNDNS(dev.Name())
			defer func() {
				dns.revert()
				if err := routes.release(); err != nil {
					log.Printf("release routes: %v", err)
				}
			}()
		}
	}

	var current atomic.Pointer[core.Client]
	current.Store(client)
	var assignedStore atomic.Value
	assignedStore.Store(assigned)

	logStats := func() {
		ip, _ := assignedStore.Load().(string)
		c := current.Load()
		if c == nil {
			log.Printf("link assigned=%s (no session)", ip)
			return
		}
		sent, recv := c.Bytes()
		log.Print(formatLinkStats(ip, c.IdleFor(), sent, recv))
	}
	if opt.statsEvery > 0 {
		go func() {
			ticker := time.NewTicker(opt.statsEvery)
			defer ticker.Stop()
			for {
				select {
				case <-sigCtx.Done():
					return
				case <-ticker.C:
					logStats()
				}
			}
		}()
	}
	go watchUSR1(sigCtx, logStats)

	go pumpTunToNet(dev, func() *core.Client { return current.Load() })

	backoff := time.Duration(0)
	for {
		sess := current.Load()
		recvDone := make(chan struct{})
		go func(c *core.Client) {
			defer close(recvDone)
			pumpNetToTun(c, dev)
		}(sess)

		lost := make(chan struct{})
		go watchInbound(sigCtx, sess, lostAfter, lost)

		select {
		case <-sigCtx.Done():
			_ = sess.Close()
			<-recvDone
			log.Println("shutting down")
			return nil
		case <-lost:
			log.Printf("inbound silence %s, reconnecting", sess.IdleFor())
			_ = sess.Close()
			<-recvDone
		case <-recvDone:
			if sigCtx.Err() != nil {
				log.Println("shutting down")
				return nil
			}
			log.Printf("session closed, reconnecting")
		}

		var next *core.Client
		var ip string
		for {
			if err := waitBackoff(sigCtx, backoff); err != nil {
				return nil
			}
			backoff = nextBackoff(backoff)
			var err error
			next, ip, err = startClient(cfg, 10*time.Second)
			if err == nil {
				break
			}
			log.Printf("reconnect failed: %v", err)
		}
		if ip != assigned {
			if assigned != "" {
				_ = exec.Command("ip", "addr", "del", assigned+"/24", "dev", dev.Name()).Run()
			}
			if err := configureClientTUN(dev.Name(), ip+"/24", cfg.MTU); err != nil {
				log.Printf("reconfigure TUN %s: %v", ip, err)
			} else {
				log.Printf("TUN address %s -> %s", assigned, ip)
			}
			assigned = ip
			assignedStore.Store(ip)
		}
		log.Printf("reconnected generation=%d assigned=%s", next.Generation(), ip)
		current.Store(next)
		backoff = 0
	}
}

func pumpTunToNet(dev *tun.Device, current func() *core.Client) {
	buf := make([]byte, 64*1024)
	for {
		n, err := dev.Read(buf)
		if err != nil {
			return
		}
		c := current()
		if c == nil {
			continue
		}
		_ = c.SendPacket(buf[:n])
	}
}

func pumpNetToTun(c *core.Client, dev *tun.Device) {
	for {
		pkt, err := c.ReceivePacket()
		if err != nil {
			return
		}
		if _, err := dev.Write(pkt); err != nil {
			return
		}
	}
}

func watchInbound(ctx context.Context, c *core.Client, lostAfter time.Duration, lost chan struct{}) {
	if lostAfter <= 0 {
		<-ctx.Done()
		return
	}
	ticker := time.NewTicker(watchdogTick(lostAfter))
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if c.IdleFor() >= lostAfter {
				select {
				case lost <- struct{}{}:
				default:
				}
				return
			}
		}
	}
}

func waitBackoff(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

const clientTUN6 = "fd99::2/64"

func configureClientTUN6(name, address string) error {
	if name == "" || address == "" {
		return nil
	}
	if out, err := exec.Command("ip", "-6", "addr", "add", address, "dev", name).CombinedOutput(); err != nil {
		s := strings.ToLower(string(out))
		if !strings.Contains(s, "file exists") {
			return fmt.Errorf("ip -6 addr add: %v: %s", err, out)
		}
	}
	return nil
}

func watchUSR1(ctx context.Context, dump func()) {
	if dump == nil {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGUSR1)
	defer signal.Stop(ch)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ch:
			dump()
		}
	}
}

func configureClientTUN(name, address string, mtu int) error {
	if out, err := exec.Command("ip", "addr", "add", address, "dev", name).CombinedOutput(); err != nil {
		s := strings.ToLower(string(out))
		if !strings.Contains(s, "file exists") {
			return fmt.Errorf("ip addr add: %v: %s", err, out)
		}
	}
	if out, err := exec.Command("ip", "link", "set", "dev", name, "mtu", fmt.Sprint(mtu), "up").CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set: %v: %s", err, out)
	}
	return nil
}
