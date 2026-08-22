package core

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestHTTPStreamRoundTrip(t *testing.T) {
	srv, err := NewServer(testConfig("127.0.0.1:0", "http"))
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	resp, err := http.Get("http://" + srv.LocalAddr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("decoy status %d, body %q", resp.StatusCode, body)
	}

	cli, err := NewClient(testConfig(srv.LocalAddr().String(), "http"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SendPacket([]byte("http-echo")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "http-echo" {
		t.Fatalf("got %q", got)
	}
}

func TestHTTPSStreamRoundTrip(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t)
	srvCfg := testConfig("127.0.0.1:0", "https")
	srvCfg.TLSCertFile = certFile
	srvCfg.TLSKeyFile = keyFile
	srv, err := NewServer(srvCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cliCfg := testConfig(srv.LocalAddr().String(), "https")
	cliCfg.TLSInsecureSkipVerify = true
	cli, err := NewClient(cliCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SendPacket([]byte("https-echo")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "https-echo" {
		t.Fatalf("got %q", got)
	}
}

func TestHTTPStreamPortHopDerivedPort(t *testing.T) {
	// freeLocalPort releases the port before the server binds it, so
	// parallel test binaries can occasionally claim it first. Retry with
	// a fresh port on "address already in use".
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		err := runHTTPPortHopProbe(t)
		if err == nil {
			return
		}
		if !strings.Contains(err.Error(), "address already in use") {
			t.Fatal(err)
		}
		lastErr = err
	}
	t.Fatalf("no free port after 5 attempts: %v", lastErr)
}

func runHTTPPortHopProbe(t *testing.T) error {
	base := freeLocalPort(t)
	cfg := testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(base)), "http")
	cfg.PortHopCount = 3
	cfg.PortHopSpread = 2048
	srv, err := NewServer(cfg)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	defer srv.Close()
	ports, err := hopPortsForConfig(cfg)
	if err != nil {
		return err
	}
	cli, err := NewClient(testConfig(net.JoinHostPort("127.0.0.1", strconv.Itoa(ports[2])), "http"))
	if err != nil {
		return err
	}
	if err := cli.Start(); err != nil {
		return fmt.Errorf("derived http port: %w", err)
	}
	return cli.Close()
}
