package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadClientConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "client.json")
	body := `{
		"serverAddr": "127.0.0.1:4789",
		"seedHex": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		"pskHex": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"generation": 3
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadClientConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServerAddr != "127.0.0.1:4789" || cfg.Generation != 3 {
		t.Fatalf("%+v", cfg)
	}
	if cfg.TunName != "chimerac0" || cfg.MTU != 1400 {
		t.Fatalf("defaults %+v", cfg)
	}
	if w := configFilePermWarning(path); w != "" {
		t.Fatalf("0600 warned: %s", w)
	}
}

func TestClientConfigPermWarning(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "open.json")
	if err := os.WriteFile(path, []byte(`{"serverAddr":"x"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if w := configFilePermWarning(path); w == "" {
		t.Fatal("expected warning")
	}
}
