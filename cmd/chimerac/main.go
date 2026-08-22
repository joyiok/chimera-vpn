// Command chimerac is the CHIMERA Linux client: generated-protocol UDP
// handshake plus either a connectivity probe (-check) or a TUN VPN.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"chimera/internal/invite"
)

// geoipDbFinal resolves the mmdb path: flag overrides config.
func geoipDbFinal(cfg clientConfig, flagVal string) string {
	if flagVal != "" {
		return flagVal
	}
	return cfg.GeoipDB
}

func main() {
	configPath := flag.String("config", "client.json", "client JSON config path")
	inviteURL := flag.String("invite", "", "chimera://v1/… share URL (overrides seed/PSK/server in -config)")
	check := flag.Bool("check", false, "handshake + assigned IP + ICMP probe; no TUN")
	jsonOut := flag.Bool("json", false, "print -check result as JSON")
	server := flag.String("server", "", "override config serverAddr (host:port)")
	transport := flag.String("transport", "", "override config transport (udp or tcp)")
	takeRoute := flag.Bool("take-route", false, "install 0.0.0.0/1 + 128.0.0.0/1 via TUN (requires root)")
	cnDirect := flag.Bool("cn-direct", false, "with -take-route: pin mainland-China routes to the underlay (domestic stays direct; requires configs embedded chnroute list)")
	geoipDb := flag.String("geoip-db", "", "mmdb database for -cn-direct route extraction (GeoLite2-Country / Country.mmdb); overrides the embedded chnroute snapshot")
	timeout := flag.Duration("timeout", 12*time.Second, "handshake / probe deadline")
	tunName := flag.String("tun", "", "override TUN interface name (default chimerac0)")
	lostAfter := flag.Duration("lost-after", defaultLinkLostAfter, "reconnect after this much inbound silence; 0 disables idle reconnect")
	statsEvery := flag.Duration("stats-interval", 30*time.Second, "log TUN byte counters this often; 0 disables")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadClientConfigOrEmpty(*configPath, *inviteURL != "")
	if err != nil {
		fatal(err)
	}
	if *inviteURL != "" {
		p, err := invite.Parse(*inviteURL)
		if err != nil {
			fatal(fmt.Errorf("invite: %w", err))
		}
		cfg.ServerAddr = p.Addr
		cfg.SeedHex = p.SeedHex
		cfg.PSKHex = p.PSKHex
		cfg.Generation = p.Generation
	}
	if *server != "" {
		cfg.ServerAddr = *server
	}
	if *transport != "" {
		cfg.Transport = *transport
	}
	if *tunName != "" {
		cfg.TunName = *tunName
	}
	if w := configFilePermWarning(*configPath); w != "" {
		log.Printf("warning: %s", w)
	}

	if *check {
		res := runCheck(cfg, *timeout)
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			if err := enc.Encode(res); err != nil {
				fatal(err)
			}
		} else {
			printCheck(res)
		}
		if !res.OK {
			os.Exit(1)
		}
		return
	}

	if err := runVPN(cfg, vpnOptions{takeRoute: *takeRoute, cnDirect: *cnDirect || cfg.CNDirect, geoipDb: geoipDbFinal(cfg, *geoipDb), lostAfter: *lostAfter, statsEvery: *statsEvery}); err != nil {
		fatal(err)
	}
}

func printCheck(res checkResult) {
	if res.Error != "" && !res.OK {
		fmt.Fprintf(os.Stderr, "check failed: %s\n", res.Error)
		return
	}
	fmt.Printf("handshake ok generation=%d assigned=%s\n", res.Generation, res.Assigned)
	fmt.Printf("probe %s rtt=%dms\n", res.Probe, res.RTTMillis)
	fmt.Println("OK")
}

func fatal(err error) {
	log.Fatalf("chimerac: %v", err)
}
