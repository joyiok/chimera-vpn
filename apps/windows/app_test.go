package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestUpsertServer(t *testing.T) {
	var list []savedServer
	list = upsertServer(list, "home", "10.0.0.1:4789")
	list = upsertServer(list, "vps", "1.2.3.4:4789")
	list = upsertServer(list, "home-lan", "10.0.0.1:4789")
	if len(list) != 2 {
		t.Fatalf("len=%d", len(list))
	}
	if list[0].Name != "home-lan" || list[0].Addr != "10.0.0.1:4789" {
		t.Fatalf("%+v", list[0])
	}
	list = upsertServer(list, "", "   ")
	if len(list) != 2 {
		t.Fatal("blank addr should be ignored")
	}
}

// writeAppConfig plants a config file next to the test binary (where
// configFilePath looks) and schedules its removal.
func writeAppConfig(t *testing.T, a *ChimeraApp, raw []byte) {
	t.Helper()
	path, err := a.configFilePath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(path) })
}

// TestStartPreservesSavedServers: connecting to a new server must not
// wipe the saved server list — neither in memory nor in the persisted
// config. Regression for a bug where start() rebuilt appConfig from
// scratch and saveConfig then wrote the wiped list to disk.
func TestStartPreservesSavedServers(t *testing.T) {
	a := NewChimeraApp()
	seed := strings.Repeat("a", 64)
	psk := strings.Repeat("b", 64)
	saved := appConfig{
		SeedHex:    seed,
		PSKHex:     psk,
		ServerAddr: "10.0.0.1:4789",
		Servers:    []savedServer{{Name: "home", Addr: "10.0.0.1:4789"}},
	}
	raw, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	writeAppConfig(t, a, raw)
	if err := a.loadConfig(); err != nil {
		t.Fatal(err)
	}

	// The default build's transport stub fails fast; a with_transport
	// build fails on the (refused) dial. Either way the config must
	// already be saved with the server list intact.
	_ = a.Start(seed, 0, psk, "127.0.0.1:4789")

	a.mu.Lock()
	got := a.cfg.Servers
	a.mu.Unlock()
	if len(got) != 1 || got[0].Addr != "10.0.0.1:4789" {
		t.Fatalf("in-memory saved servers wiped: %+v", got)
	}
	b := NewChimeraApp()
	if err := b.loadConfig(); err != nil {
		t.Fatal(err)
	}
	if len(b.cfg.Servers) != 1 || b.cfg.Servers[0].Addr != "10.0.0.1:4789" {
		t.Fatalf("persisted saved servers wiped: %+v", b.cfg.Servers)
	}
}

// TestLoadConfigBackfillsHopSpread: a legacy config with portHopCount > 1
// but no portHopSpread must migrate with the default spread, or the next
// start() fails validation.
func TestLoadConfigBackfillsHopSpread(t *testing.T) {
	a := NewChimeraApp()
	disk := map[string]any{
		"seedHex":      strings.Repeat("a", 64),
		"pskHex":       strings.Repeat("b", 64),
		"serverAddr":   "127.0.0.1:4789",
		"portHopCount": 3,
		// no portHopSpread: legacy config
	}
	raw, err := json.Marshal(disk)
	if err != nil {
		t.Fatal(err)
	}
	writeAppConfig(t, a, raw)
	if err := a.loadConfig(); err != nil {
		t.Fatal(err)
	}
	if a.cfg.PortHopCount != 3 || a.cfg.PortHopSpread != 2048 {
		t.Fatalf("hop migration wrong: count=%d spread=%d", a.cfg.PortHopCount, a.cfg.PortHopSpread)
	}
}

// TestStopWithoutStartIsSafe pins the lifecycle intent flag: Stop must
// record "user wants disconnected" so the watchdog never reconnects
// behind the user's back.
func TestStopWithoutStartIsSafe(t *testing.T) {
	a := NewChimeraApp()
	if err := a.Stop(); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	want := a.wantConnected
	status := a.status
	a.mu.Unlock()
	if want {
		t.Fatal("wantConnected must be false after Stop")
	}
	if status != "disconnected" {
		t.Fatalf("status = %s, want disconnected", status)
	}
}

// TestStartRejectsInvalidTransport keeps the validation surface honest
// with the frontend, which offers udp/tcp/websocket/wss.
func TestStartRejectsInvalidTransport(t *testing.T) {
	a := NewChimeraApp()
	err := a.StartWithTransport(strings.Repeat("a", 64), 0, strings.Repeat("b", 64), "127.0.0.1:4789", "quic")
	if err == nil {
		t.Fatal("invalid transport accepted")
	}
}
