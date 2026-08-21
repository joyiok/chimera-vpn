package core

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
)

// hopPortsForConfig derives the ordered port sequence shared by both
// endpoints. The configured base port is always first; additional ports are
// deterministic HMAC outputs over the seed and generation, so no control
// channel is needed to agree on the sequence.
func hopPortsForConfig(cfg Config) ([]int, error) {
	if cfg.PortHopCount <= 1 {
		_, port, err := net.SplitHostPort(cfg.ServerAddr)
		if err != nil {
			return nil, fmt.Errorf("parse server address %q: %w", cfg.ServerAddr, err)
		}
		p, err := strconv.Atoi(port)
		if err != nil || p < 0 || p > 65535 {
			return nil, fmt.Errorf("invalid base port in %q", cfg.ServerAddr)
		}
		return []int{p}, nil
	}

	_, portStr, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("parse server address %q: %w", cfg.ServerAddr, err)
	}
	base, err := strconv.Atoi(portStr)
	if err != nil || base < 1 || base > 65535 {
		return nil, fmt.Errorf("invalid base port in %q", cfg.ServerAddr)
	}
	if base == 0 {
		return nil, fmt.Errorf("port hopping requires a fixed base port, got %q", cfg.ServerAddr)
	}
	seed, err := parseHex32(cfg.SeedHex, "seed")
	if err != nil {
		return nil, err
	}
	spread := cfg.PortHopSpread
	if spread <= 0 {
		spread = 2048
	}
	if spread > 60000 {
		spread = 60000
	}

	ports := []int{base}
	seen := map[int]bool{base: true}
	for counter := uint64(0); len(ports) < cfg.PortHopCount && counter < 4096; counter++ {
		mac := hmac.New(sha256.New, seed)
		mac.Write([]byte("chimera-pgc/0/port-hop\x00"))
		var gen [8]byte
		binary.BigEndian.PutUint64(gen[:], cfg.Generation)
		mac.Write(gen[:])
		var cnt [8]byte
		binary.BigEndian.PutUint64(cnt[:], counter)
		mac.Write(cnt[:])
		sum := mac.Sum(nil)
		offset := int(binary.BigEndian.Uint64(sum[:8])%uint64(spread-1)) + 1
		candidate := base + offset
		if candidate > 65535 {
			candidate = 1024 + (candidate-1024)%(65535-1024+1)
		}
		if candidate == base || seen[candidate] {
			continue
		}
		seen[candidate] = true
		ports = append(ports, candidate)
	}
	if len(ports) < cfg.PortHopCount {
		return nil, fmt.Errorf("could not derive %d distinct ports in spread %d", cfg.PortHopCount, spread)
	}
	sort.Ints(ports)
	return ports, nil
}

// hopAddrsForConfig returns dialable server addresses in probe order.
func hopAddrsForConfig(cfg Config) ([]string, error) {
	ports, err := hopPortsForConfig(cfg)
	if err != nil {
		return nil, err
	}
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("parse server address %q: %w", cfg.ServerAddr, err)
	}
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return out, nil
}

// listenAddrsForPorts returns bindable addresses for a server listener.
func listenAddrsForPorts(cfg Config, ports []int) ([]string, error) {
	host, _, err := net.SplitHostPort(cfg.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("parse server address %q: %w", cfg.ServerAddr, err)
	}
	out := make([]string, 0, len(ports))
	for _, port := range ports {
		out = append(out, net.JoinHostPort(host, strconv.Itoa(port)))
	}
	return out, nil
}
