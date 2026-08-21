package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
)

// clientConfig matches configs/client.example.json (camelCase, same as the
// Windows GUI file) plus optional Linux TUN fields.
type clientConfig struct {
	ServerAddr       string `json:"serverAddr"`
	Transport        string `json:"transport"`
	PortHopCount     int    `json:"portHopCount"`
	PortHopSpread    int    `json:"portHopSpread"`
	TLSCAFile        string `json:"tlsCAFile"`
	TLSInsecure      bool   `json:"tlsInsecureSkipVerify"`
	SeedHex          string `json:"seedHex"`
	Generation       uint64 `json:"generation"`
	PSKHex           string `json:"pskHex"`
	Cipher           string `json:"cipher"`
	TunName          string `json:"tunName"`
	MTU              int    `json:"mtu"`
	TakeDefaultRoute bool   `json:"takeDefaultRoute"`
}

func defaultClientConfig() clientConfig {
	return clientConfig{
		TunName: "chimerac0",
		MTU:     1400,
	}
}

func loadClientConfigOrEmpty(path string, inviteOK bool) (clientConfig, error) {
	if inviteOK {
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				return defaultClientConfig(), nil
			}
			return clientConfig{}, err
		}
	}
	return loadClientConfig(path)
}

func loadClientConfig(path string) (clientConfig, error) {
	cfg := defaultClientConfig()
	raw, err := os.ReadFile(path)
	if err != nil {
		return cfg, fmt.Errorf("read %s: %w", path, err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.TunName == "" {
		cfg.TunName = "chimerac0"
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1400
	}
	return cfg, nil
}

func configFilePermWarning(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	perm := info.Mode().Perm()
	if !isWorldReadable(perm) {
		return ""
	}
	return fmt.Sprintf("%s mode %04o is readable by group/other; PSK lives in this file", path, perm)
}

func isWorldReadable(mode fs.FileMode) bool {
	return mode.Perm()&0077 != 0
}
