package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"chimera/internal/tunnel"
)

func TestLoadServerConfigDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "missing.json")
	cfg, err := loadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	coreCfg, err := toCoreConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if coreCfg.GenerationWindow != 2 {
		t.Fatalf("window=%d want 2", coreCfg.GenerationWindow)
	}
	if coreCfg.JitterMax != tunnel.DefaultJitterMax {
		t.Fatalf("jitter=%s want %s", coreCfg.JitterMax, tunnel.DefaultJitterMax)
	}
	if coreCfg.MaxSessions != 256 {
		t.Fatalf("sessions=%d", coreCfg.MaxSessions)
	}
}

func TestToCoreConfigExplicitWindowZero(t *testing.T) {
	zero := 0
	cfg := defaultConfig()
	cfg.GenerationWindow = &zero
	cfg.JitterMS = -1
	coreCfg, err := toCoreConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if coreCfg.GenerationWindow != 0 {
		t.Fatalf("window=%d want 0", coreCfg.GenerationWindow)
	}
	if coreCfg.JitterMax != 0 {
		t.Fatalf("jitter=%s want 0", coreCfg.JitterMax)
	}
}

func TestLoadServerConfigJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server.json")
	body := `{
		"listen": "127.0.0.1:9",
		"seed_hex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"psk_hex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"generation_window": 1,
		"jitter_ms": 15
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadServerConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	coreCfg, err := toCoreConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if coreCfg.ServerAddr != "127.0.0.1:9" {
		t.Fatalf("listen %s", coreCfg.ServerAddr)
	}
	if coreCfg.GenerationWindow != 1 {
		t.Fatalf("window=%d", coreCfg.GenerationWindow)
	}
	if coreCfg.JitterMax != 15*time.Millisecond {
		t.Fatalf("jitter=%s", coreCfg.JitterMax)
	}
	if w := configFilePermWarning(path); w != "" {
		t.Fatalf("0600 should not warn: %s", w)
	}
}

func TestConfigPermWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "open.json")
	if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := configFilePermWarning(path); w == "" {
		t.Fatal("expected warning for 0644 config")
	}
}

func TestIPAddrAlreadyPresent(t *testing.T) {
	if !ipAddrAlreadyPresent([]byte("RTNETLINK answers: File exists")) {
		t.Fatal("english File exists not detected")
	}
	if ipAddrAlreadyPresent([]byte("permission denied")) {
		t.Fatal("unrelated error treated as exists")
	}
}
