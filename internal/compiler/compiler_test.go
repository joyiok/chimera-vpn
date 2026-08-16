package compiler

import (
	"crypto/sha256"
	"fmt"
	"net"
	"testing"

	"chimera/internal/genome"
)

func testSeed(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("compiler-test-seed-%d", i)))
	return h[:]
}

func testPSK(i int) []byte {
	h := sha256.Sum256([]byte(fmt.Sprintf("compiler-test-psk-%d", i)))
	return h[:]
}

func TestEndToEndManySeeds(t *testing.T) {
	for i := 0; i < 120; i++ {
		g, err := genome.Generate(testSeed(i), uint64(i%5))
		if err != nil {
			t.Fatal(err)
		}
		psk := testPSK(i)
		if err := runEndToEnd(g, psk); err != nil {
			t.Fatalf("seed %d (pattern %s): %v", i, g.HandshakePattern, err)
		}
	}
}

func runEndToEnd(g *genome.ProtocolGenome, psk []byte) error {
	cp, err := Compile(g, psk)
	if err != nil {
		return err
	}
	client, err := NewHandshake(cp, genome.DirClient, psk)
	if err != nil {
		return err
	}
	server, err := NewHandshake(cp, genome.DirServer, psk)
	if err != nil {
		return err
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()

	cd := make(chan error, 1)
	sd := make(chan error, 1)
	go func() { cd <- client.Run(left) }()
	go func() { sd <- server.Run(right) }()
	if err := <-cd; err != nil {
		return err
	}
	if err := <-sd; err != nil {
		return err
	}
	cs, err := client.Finish()
	if err != nil {
		return err
	}
	ss, err := server.Finish()
	if err != nil {
		return err
	}

	payload := []byte("application payload across a generated protocol")
	type res struct {
		m   *Message
		err error
	}
	ch := make(chan res, 1)
	go func() { m, err := ss.Recv(right); ch <- res{m, err} }()
	if err := cs.Send(left, payload); err != nil {
		return err
	}
	r := <-ch
	if r.err != nil {
		return r.err
	}
	if string(r.m.Payload) != string(payload) {
		return fmt.Errorf("payload mismatch: %q", r.m.Payload)
	}
	return nil
}

func TestEveryMessageRoundTrips(t *testing.T) {
	g, err := genome.Generate(testSeed(999), 3)
	if err != nil {
		t.Fatal(err)
	}
	psk := testPSK(999)
	cp, err := Compile(g, psk)
	if err != nil {
		t.Fatal(err)
	}
	codecs, err := cp.NewHandshakeCodecs()
	if err != nil {
		t.Fatal(err)
	}
	for i, enc := range codecs {
		dec, err := NewMessageCodec(g.Handshake[i], codecsKey(cp, g.Handshake[i]))
		if err != nil {
			t.Fatal(err)
		}
		inject := map[string][]byte{}
		if messageHasKey(g.Handshake[i]) {
			inject[genome.FieldKey] = make([]byte, 32)
		}
		var payload []byte
		if g.Handshake[i].HasPayload {
			payload = []byte("x")
		}
		frame, segs, err := enc.Encode(payload, inject, nil)
		if err != nil {
			t.Fatalf("encode %s: %v", g.Handshake[i].Name, err)
		}
		var full []byte
		for _, s := range segs {
			full = append(full, s...)
		}
		if len(full) != len(frame) {
			t.Fatalf("%s: segments did not reassemble", g.Handshake[i].Name)
		}
		if _, err := dec.Decode(frame); err != nil {
			t.Fatalf("decode %s: %v", g.Handshake[i].Name, err)
		}
	}
}

func codecsKey(cp *CompiledProtocol, spec genome.MessageSpec) []byte {
	if spec.Direction == genome.DirServer {
		return cp.Bootstrap.S2C
	}
	return cp.Bootstrap.C2S
}

func TestTamperDetection(t *testing.T) {
	g, _ := genome.Generate(testSeed(777), 0)
	psk := testPSK(777)
	cp, _ := Compile(g, psk)
	codecs, _ := cp.NewHandshakeCodecs()
	enc := codecs[0]
	dec, _ := NewMessageCodec(g.Handshake[0], codecsKey(cp, g.Handshake[0]))
	var payload []byte
	if g.Handshake[0].HasPayload {
		payload = []byte("secret")
	}
	frame, _, err := enc.Encode(payload, map[string][]byte{genome.FieldKey: make([]byte, 32)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), frame...)
	bad[len(bad)-1] ^= 0x01
	if _, err := dec.Decode(bad); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

func TestReadFrameStream(t *testing.T) {
	g, _ := genome.Generate(testSeed(555), 0)
	psk := testPSK(555)
	cp, _ := Compile(g, psk)
	codecs, _ := cp.NewHandshakeCodecs()
	for i, enc := range codecs {
		spec := g.Handshake[i]
		frame, segs, err := enc.Encode(nil, map[string][]byte{genome.FieldKey: make([]byte, 32)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Concatenate with a trailing marker so over/under-reads are visible.
		stream := append([]byte{}, frame...)
		stream = append(stream, 0xAA, 0xBB)
		left, right := net.Pipe()
		go func() {
			for _, s := range segs {
				left.Write(s)
			}
			left.Write([]byte{0xAA, 0xBB})
			left.Close()
		}()
		got, err := ReadFrame(right, spec)
		if err != nil {
			t.Fatalf("message %d: %v", i, err)
		}
		if string(got) != string(frame) {
			t.Fatalf("message %d: stream frame mismatch", i)
		}
		right.Close()
		_ = left
	}
}

// TestClientFirstFramesDifferAcrossSeeds: UPGen's security argument needs
// each (seed, generation) to look like a different unknown protocol. The
// first client-to-server datagram must not be a shared magic blob.
func TestClientFirstFramesDifferAcrossSeeds(t *testing.T) {
	seen := map[string]int{}
	for i := 0; i < 40; i++ {
		g, err := genome.Generate(testSeed(8000+i), 0)
		if err != nil {
			t.Fatal(err)
		}
		if g.Handshake[0].Direction != genome.DirClient {
			continue
		}
		psk := testPSK(8000 + i)
		cp, err := Compile(g, psk)
		if err != nil {
			t.Fatal(err)
		}
		h, err := NewHandshake(cp, genome.DirClient, psk)
		if err != nil {
			t.Fatal(err)
		}
		frame, _, err := h.EncodeStep()
		if err != nil {
			t.Fatal(err)
		}
		key := string(frame[:min(16, len(frame))])
		seen[key]++
	}
	if len(seen) < 8 {
		t.Fatalf("first-client frames too similar across seeds: %d distinct prefixes", len(seen))
	}
}
