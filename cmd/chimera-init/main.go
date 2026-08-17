// Command chimera-init writes a matching server.json + client.json pair
// with a fresh 256-bit seed and PSK. Secrets are never printed in full
// unless -print-secrets is set.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

type initServer struct {
	Listen           string  `json:"listen"`
	SeedHex          string  `json:"seed_hex"`
	Generation       uint64  `json:"generation"`
	PSKHex           string  `json:"psk_hex"`
	ClientCIDR       string  `json:"client_cidr"`
	Cipher           string  `json:"cipher"`
	KeepaliveSec     int     `json:"keepalive_sec"`
	IdleTimeoutSec   int     `json:"idle_timeout_sec"`
	RateLimitKBps    int     `json:"rate_limit_kbps"`
	MaxSessions      int     `json:"max_sessions"`
	DisableDecoy     bool    `json:"disable_decoy"`
	DisableShape     bool    `json:"disable_shape"`
	JitterMS         int     `json:"jitter_ms"`
	GenerationWindow int     `json:"generation_window"`
	ReplayPath       string  `json:"replay_path"`
	Tun              initTun `json:"tun"`
}

type initTun struct {
	Name    string `json:"name"`
	Address string `json:"address"`
	MTU     int    `json:"mtu"`
}

type initClient struct {
	ServerAddr       string `json:"serverAddr"`
	SeedHex          string `json:"seedHex"`
	Generation       uint64 `json:"generation"`
	PSKHex           string `json:"pskHex"`
	Cipher           string `json:"cipher"`
	TunName          string `json:"tunName"`
	MTU              int    `json:"mtu"`
	TakeDefaultRoute bool   `json:"takeDefaultRoute"`
}

func main() {
	dir := flag.String("dir", ".", "output directory")
	listen := flag.String("listen", "0.0.0.0:4789", "server listen address")
	server := flag.String("server", "127.0.0.1:4789", "client serverAddr (host:port the client dials)")
	dev := flag.Bool("dev", false, "local self-test defaults: 127.0.0.1:0 listen, memory replay, no default-route")
	replayPath := flag.String("replay-path", "/var/lib/chimera/handshake.replay", "handshake replay file; empty = memory only")
	printSecrets := flag.Bool("print-secrets", false, "print seed and PSK to stdout (otherwise only fingerprints)")
	flag.Parse()

	if err := os.MkdirAll(*dir, 0o700); err != nil {
		fatal(err)
	}

	seed, psk, err := randomKeys()
	if err != nil {
		fatal(err)
	}
	seedHex := hex.EncodeToString(seed)
	pskHex := hex.EncodeToString(psk)

	listenAddr := *listen
	clientAddr := *server
	replay := *replayPath
	takeRoute := true
	if *dev {
		listenAddr = "127.0.0.1:0"
		clientAddr = "127.0.0.1:0"
		replay = ""
		takeRoute = false
	}

	srv := initServer{
		Listen:           listenAddr,
		SeedHex:          seedHex,
		Generation:       0,
		PSKHex:           pskHex,
		ClientCIDR:       "10.99.0.0/24",
		KeepaliveSec:     25,
		IdleTimeoutSec:   180,
		MaxSessions:      256,
		JitterMS:         20,
		GenerationWindow: 2,
		ReplayPath:       replay,
		Tun:              initTun{Name: "chimera0", Address: "10.99.0.1/24", MTU: 1400},
	}
	cli := initClient{
		ServerAddr:       clientAddr,
		SeedHex:          seedHex,
		Generation:       0,
		PSKHex:           pskHex,
		TunName:          "chimerac0",
		MTU:              1400,
		TakeDefaultRoute: takeRoute,
	}

	if err := writeJSON(filepath.Join(*dir, "server.json"), srv); err != nil {
		fatal(err)
	}
	if err := writeJSON(filepath.Join(*dir, "client.json"), cli); err != nil {
		fatal(err)
	}

	fmt.Printf("wrote %s/server.json and %s/client.json (mode 0600)\n", *dir, *dir)
	fmt.Printf("seed_fp=%s psk_fp=%s listen=%s client_dials=%s\n", fingerprint(seed), fingerprint(psk), listenAddr, clientAddr)
	if *printSecrets {
		fmt.Printf("seed_hex=%s\npsk_hex=%s\n", seedHex, pskHex)
	}
	if *dev {
		fmt.Println("next: chimerad -config DIR/server.json -no-tun")
		fmt.Println("      chimerac -config DIR/client.json -check -server <bound from server log>")
	} else {
		fmt.Println("next: chmod 0600 the JSON files, chimerad -check-config, then systemd + chimerac/-take-route")
	}
}

func randomKeys() (seed, psk []byte, err error) {
	seed = make([]byte, 32)
	psk = make([]byte, 32)
	if _, err = rand.Read(seed); err != nil {
		return nil, nil, err
	}
	if _, err = rand.Read(psk); err != nil {
		return nil, nil, err
	}
	return seed, psk, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}

func fingerprint(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	return hex.EncodeToString(b[:4])
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "chimera-init: %v\n", err)
	os.Exit(1)
}
