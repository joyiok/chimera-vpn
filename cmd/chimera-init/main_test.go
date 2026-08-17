package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteJSONModeAndRoundTrip(t *testing.T) {
	dir := t.TempDir()
	seed := make([]byte, 32)
	psk := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
		psk[i] = byte(255 - i)
	}
	srv := initServer{
		Listen:     "127.0.0.1:0",
		SeedHex:    hex.EncodeToString(seed),
		PSKHex:     hex.EncodeToString(psk),
		ClientCIDR: "10.99.0.0/24",
		ReplayPath: "",
		Tun:        initTun{Name: "chimera0", Address: "10.99.0.1/24", MTU: 1400},
	}
	path := filepath.Join(dir, "server.json")
	if err := writeJSON(path, srv); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatalf("mode %04o", info.Mode().Perm())
	}
	var got initServer
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got.Listen != "127.0.0.1:0" || got.ReplayPath != "" || got.SeedHex != srv.SeedHex {
		t.Fatalf("%+v", got)
	}
}

func TestRandomKeysLength(t *testing.T) {
	seed, psk, err := randomKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != 32 || len(psk) != 32 {
		t.Fatalf("len seed=%d psk=%d", len(seed), len(psk))
	}
	if hex.EncodeToString(seed) == hex.EncodeToString(psk) {
		t.Fatal("seed reused as psk")
	}
}
