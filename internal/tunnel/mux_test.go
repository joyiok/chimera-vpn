package tunnel

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"chimera/internal/compiler"
	"chimera/internal/genome"
)

func TestServerMuxThreeClients(t *testing.T) {
	g, err := genome.Generate(seedFor(4000), 0)
	if err != nil {
		t.Fatal(err)
	}
	psk := pskFor(4000)
	cp, err := compiler.Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()
	serverAddr := serverConn.LocalAddr()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	mux := NewServerMux(serverConn, cp, psk)
	go mux.Run(ctx)

	const clients = 3
	clientConns := make([]net.PacketConn, clients)
	for i := 0; i < clients; i++ {
		conn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		clientConns[i] = conn
		defer conn.Close()
	}

	clientTuns := make([]*PacketTunnel, clients)
	var wg sync.WaitGroup
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
			if err != nil {
				t.Errorf("client %d: %v", i, err)
				return
			}
			sess, err := ClientHandshake(clientConns[i], serverAddr, h)
			if err != nil {
				t.Errorf("client %d handshake: %v", i, err)
				return
			}
			clientTuns[i] = NewPacketTunnel(clientConns[i], serverAddr, sess)
		}(i)
	}
	wg.Wait()
	for i := range clientTuns {
		if clientTuns[i] == nil {
			t.Fatal("a client failed to connect")
		}
	}

	serverTuns := make([]*ServerTunnel, 0, clients)
	acceptCtx, cancelAccept := context.WithTimeout(ctx, 5*time.Second)
	defer cancelAccept()
	for i := 0; i < clients; i++ {
		st, err := mux.Accept(acceptCtx)
		if err != nil {
			t.Fatalf("accept %d: %v", i, err)
		}
		serverTuns = append(serverTuns, st)
	}

	// Each client sends a unique marker.
	for i := 0; i < clients; i++ {
		if err := clientTuns[i].SendPacket([]byte(fmt.Sprintf("marker-%d", i))); err != nil {
			t.Fatal(err)
		}
	}

	// Match server tunnels to markers by receiving one packet from each.
	serverByMarker := map[string]*ServerTunnel{}
	for i := 0; i < clients; i++ {
		st := serverTuns[i]
		done := make(chan []byte, 1)
		go func() {
			pkt, _ := st.ReceivePacket()
			done <- pkt
		}()
		select {
		case pkt := <-done:
			serverByMarker[string(pkt)] = st
		case <-time.After(3 * time.Second):
			t.Fatal("server did not receive marker")
		}
	}
	for i := 0; i < clients; i++ {
		marker := fmt.Sprintf("marker-%d", i)
		st, ok := serverByMarker[marker]
		if !ok {
			t.Fatalf("marker %s missing", marker)
		}
		// Reply and verify the right client gets it.
		reply := []byte("reply-" + marker)
		go func(st *ServerTunnel) { _ = st.SendPacket(reply) }(st)
		got := make(chan []byte, 1)
		go func(i int) {
			pkt, _ := clientTuns[i].ReceivePacket()
			got <- pkt
		}(i)
		select {
		case pkt := <-got:
			if string(pkt) != string(reply) {
				t.Fatalf("client %d got %q, want %q", i, pkt, reply)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("client %d did not receive reply", i)
		}
	}

	for _, st := range serverTuns {
		st.Close()
	}
	for _, ct := range clientTuns {
		ct.Close()
	}
	for _, c := range clientConns {
		c.Close()
	}
}

func TestServerMuxHandshakePatterns(t *testing.T) {
	for i := 0; i < 30; i++ {
		g, err := genome.Generate(seedFor(5000+i), uint64(i%7))
		if err != nil {
			t.Fatal(err)
		}
		psk := pskFor(5000 + i)
		cp, err := compiler.Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}

		serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		serverAddr := serverConn.LocalAddr()

		ctx, cancel := context.WithCancel(context.Background())
		mux := NewServerMux(serverConn, cp, psk)
		go mux.Run(ctx)

		clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			serverConn.Close()
			cancel()
			t.Fatal(err)
		}
		h, err := compiler.NewHandshake(cp, genome.DirClient, psk)
		if err != nil {
			t.Fatal(err)
		}
		sess, err := ClientHandshake(clientConn, serverAddr, h)
		if err != nil {
			t.Fatalf("seed %d pattern %s: %v", i, g.HandshakePattern, err)
		}
		ct := NewPacketTunnel(clientConn, serverAddr, sess)

		acceptCtx, acceptCancel := context.WithTimeout(ctx, 5*time.Second)
		st, err := mux.Accept(acceptCtx)
		acceptCancel()
		if err != nil {
			t.Fatalf("seed %d pattern %s accept: %v", i, g.HandshakePattern, err)
		}

		if err := ct.SendPacket([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		ch := make(chan []byte, 1)
		go func() { p, _ := st.ReceivePacket(); ch <- p }()
		select {
		case p := <-ch:
			if string(p) != "ping" {
				t.Fatalf("seed %d: got %q", i, p)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("seed %d pattern %s: no packet", i, g.HandshakePattern)
		}

		ct.Close()
		st.Close()
		serverConn.Close()
		clientConn.Close()
		cancel()
	}
}
