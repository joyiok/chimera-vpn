package tunnel

import (
	"crypto/sha256"
	"fmt"
	"net"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

func seedFor(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("tunnel-test-seed-%d", i)))
	return h[:]
}
func pskFor(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("tunnel-test-psk-%d", i)))
	return h[:]
}

func TestUDPPacketTunnelManySeeds(t *testing.T) {
	for i := 0; i < 60; i++ {
		if err := runOne(t, i); err != nil {
			t.Fatalf("seed %d: %v", i, err)
		}
	}
}

func runOne(t *testing.T, i int) error {
	t.Helper()
	g, err := genome.Generate(seedFor(i), uint64(i%7))
	if err != nil {
		return err
	}
	psk := pskFor(i)
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		return err
	}

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr()

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer clientConn.Close()

	serverH, err := compiler.NewHandshake(cp, genome.DirServer, psk)
	if err != nil {
		return err
	}
	clientH, err := compiler.NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		return err
	}

	type sres struct {
		tun *PacketTunnel
		err error
	}
	serverDone := make(chan sres, 1)
	clientDone := make(chan sres, 1)

	go func() {
		addr, sess, err := ServerHandshake(serverConn, serverH)
		if err != nil {
			serverDone <- sres{err: err}
			return
		}
		serverDone <- sres{tun: &PacketTunnel{conn: serverConn, peer: addr, sess: sess}}
	}()
	go func() {
		sess, err := ClientHandshake(clientConn, serverAddr, clientH)
		if err != nil {
			clientDone <- sres{err: err}
			return
		}
		clientDone <- sres{tun: &PacketTunnel{conn: clientConn, peer: serverAddr, sess: sess}}
	}()

	cr := <-clientDone
	if cr.err != nil {
		return fmt.Errorf("client handshake: %w", cr.err)
	}
	sr := <-serverDone
	if sr.err != nil {
		return fmt.Errorf("server handshake: %w", sr.err)
	}
	defer cr.tun.Close()
	defer sr.tun.Close()

	// Client -> server.
	payload := []byte{0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 10, 99, 0, 2, 10, 99, 0, 1}
	type rx struct {
		pkt []byte
		err error
	}
	ch := make(chan rx, 1)
	go func() { p, e := sr.tun.ReceivePacket(); ch <- rx{p, e} }()
	if err := cr.tun.SendPacket(payload); err != nil {
		return err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if len(r.pkt) != len(payload) {
			return fmt.Errorf("c2s packet length %d != %d", len(r.pkt), len(payload))
		}
	case <-time.After(3 * time.Second):
		return fmt.Errorf("timeout waiting c2s packet")
	}

	// Server -> client.
	reply := []byte{0x45, 0, 0, 20, 0, 1, 0, 0, 64, 17, 0, 0, 10, 99, 0, 1, 10, 99, 0, 2}
	go func() { p, e := cr.tun.ReceivePacket(); ch <- rx{p, e} }()
	if err := sr.tun.SendPacket(reply); err != nil {
		return err
	}
	select {
	case r := <-ch:
		if r.err != nil {
			return r.err
		}
		if len(r.pkt) != len(reply) {
			return fmt.Errorf("s2c packet length %d != %d", len(r.pkt), len(reply))
		}
	case <-time.After(3 * time.Second):
		return fmt.Errorf("timeout waiting s2c packet")
	}
	return nil
}
