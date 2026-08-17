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
)

func main() {
	configPath := flag.String("config", "client.json", "client JSON config path")
	check := flag.Bool("check", false, "handshake + assigned IP + ICMP probe; no TUN")
	jsonOut := flag.Bool("json", false, "print -check result as JSON")
	server := flag.String("server", "", "override config serverAddr (host:port)")
	takeRoute := flag.Bool("take-route", false, "install 0.0.0.0/1 + 128.0.0.0/1 via TUN (requires root)")
	timeout := flag.Duration("timeout", 12*time.Second, "handshake / probe deadline")
	tunName := flag.String("tun", "", "override TUN interface name (default chimerac0)")
	lostAfter := flag.Duration("lost-after", defaultLinkLostAfter, "reconnect after this much inbound silence; 0 disables idle reconnect")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadClientConfig(*configPath)
	if err != nil {
		fatal(err)
	}
	if *server != "" {
		cfg.ServerAddr = *server
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

	if err := runVPN(cfg, vpnOptions{takeRoute: *takeRoute, lostAfter: *lostAfter}); err != nil {
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
