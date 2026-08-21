package core

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"chimera/internal/tunnel"
)

func startProbeServer(t *testing.T, mode tunnel.StreamProbeMode, timeout time.Duration) *Server {
	t.Helper()
	cfg := testConfig("127.0.0.1:0", "tcp")
	cfg.StreamDecoyMode = mode
	cfg.StreamDecoyTimeout = timeout
	cfg.StreamDecoyMaxPending = 4
	srv, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	return srv
}

func readOrTimeout(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if n == 0 {
		return nil, err
	}
	return buf[:n], err
}

func TestStreamProbeCloseMode(t *testing.T) {
	srv := startProbeServer(t, tunnel.StreamProbeClose, 200*time.Millisecond)
	conn, err := net.Dial("tcp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("this is not a chimera frame")); err != nil {
		t.Fatal(err)
	}
	if _, err := readOrTimeout(conn, time.Second); err == nil {
		t.Fatal("close mode should not return probe data")
	}
}

func TestStreamProbeSilentMode(t *testing.T) {
	srv := startProbeServer(t, tunnel.StreamProbeSilent, 250*time.Millisecond)
	conn, err := net.Dial("tcp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("random probe bytes")); err != nil {
		t.Fatal(err)
	}

	// While the decoy window is open the server must stay silent.
	if data, err := readOrTimeout(conn, 120*time.Millisecond); err == nil {
		t.Fatalf("silent decoy answered a probe: %x", data)
	}
	// After the timeout the server closes the connection without answering.
	if _, err := readOrTimeout(conn, 2*time.Second); err == nil || err == io.EOF {
		if err == nil {
			t.Fatal("expected close after silent decoy timeout")
		}
	}
}

func TestStreamProbeTLSSendsFatalAlert(t *testing.T) {
	srv := startProbeServer(t, tunnel.StreamProbeTLS, 250*time.Millisecond)
	conn, err := net.Dial("tcp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	hello := append([]byte{0x16, 0x03, 0x03, 0x00, 0x10}, make([]byte, 16)...)
	if _, err := conn.Write(hello); err != nil {
		t.Fatal(err)
	}
	got, err := readOrTimeout(conn, time.Second)
	if err != nil {
		t.Fatalf("expected TLS alert: %v", err)
	}
	want := []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28}
	if len(got) != len(want) {
		t.Fatalf("alert = %x, want %x", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("alert = %x, want %x", got, want)
		}
	}
}

func TestStreamProbeTLSModeNonTLSStaysSilent(t *testing.T) {
	srv := startProbeServer(t, tunnel.StreamProbeTLS, 200*time.Millisecond)
	conn, err := net.Dial("tcp", srv.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("not a client hello")); err != nil {
		t.Fatal(err)
	}
	if data, err := readOrTimeout(conn, 100*time.Millisecond); err == nil {
		t.Fatalf("non-TLS probe should stay silent, got %x", data)
	}
}

func TestStreamProbeDoesNotBreakValidClients(t *testing.T) {
	srv := startProbeServer(t, tunnel.StreamProbeSilent, 200*time.Millisecond)
	cli, err := NewClient(testConfig(srv.LocalAddr().String(), "tcp"))
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := srv.Accept(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SendPacket([]byte("still works")); err != nil {
		t.Fatal(err)
	}
	got, err := cli.ReceivePacket()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "still works" {
		t.Fatalf("got %q", got)
	}
}
