//go:build windows

package bridge

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/tun"
)

// platformStart creates a Wintun adapter named "Chimera", assigns ip/24 and
// DNS servers through netsh, then starts TUN->core and core->TUN loops.
func platformStart(ip string, mtu int, send Sender, recv Receiver) (*Bridge, error) {
	dev, err := tun.CreateTUN("Chimera", mtu)
	if err != nil {
		return nil, fmt.Errorf("wintun create: %w (place wintun.dll next to ChimeraClient.exe or install the driver)", err)
	}
	name, err := dev.Name()
	if err != nil {
		dev.Close()
		return nil, err
	}

	if err := configureAdapter(name, ip); err != nil {
		dev.Close()
		return nil, err
	}
	log.Printf("[bridge] Wintun adapter %s configured with %s/24", name, ip)

	ctx, cancel := context.WithCancel(context.Background())
	b := &Bridge{
		dev:  dev,
		name: name,
		ip:   ip,
		send: send,
		recv: recv,
		done: make(chan struct{}),
	}
	go b.run(ctx, cancel)
	return b, nil
}

// run drives both packet pumps until ctx is cancelled or either loop dies.
func (b *Bridge) run(ctx context.Context, cancel context.CancelFunc) {
	defer close(b.done)
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		bufs := [][]byte{make([]byte, 64*1024)}
		sizes := []int{0}
		for {
			n, err := b.dev.Read(bufs, sizes, 0)
			if err != nil {
				log.Printf("[bridge] TUN read stopped: %v", err)
				cancel()
				return
			}
			for i := 0; i < n; i++ {
				if err := b.send(bufs[i][:sizes[i]]); err != nil {
					log.Printf("[bridge] core send failed: %v", err)
					cancel()
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		for {
			pkt, err := b.recv()
			if err != nil {
				log.Printf("[bridge] core receive stopped: %v", err)
				cancel()
				return
			}
			if _, err := b.dev.Write([][]byte{pkt}, 0); err != nil {
				log.Printf("[bridge] TUN write failed: %v", err)
				cancel()
				return
			}
		}
	}()

	<-ctx.Done()
	b.dev.Close()
	wg.Wait()
}

func configureAdapter(name, ip string) error {
	run := func(args ...string) error {
		cmd := exec.Command("netsh", args...)
		cmd.SysProcAttr = &sysProcAttr
		out, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("netsh %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err := run("interface", "ipv4", "set", "address", "name="+name, "source=static", "addr="+ip, "mask=255.255.255.0"); err != nil {
		return err
	}
	if err := run("interface", "ipv4", "set", "dnsservers", "name="+name, "source=static", "address=1.1.1.1", "register=primary"); err != nil {
		return err
	}
	return run("interface", "ipv4", "add", "dnsservers", "name="+name, "address=8.8.8.8", "index=2")
}
