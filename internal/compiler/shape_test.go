package compiler

import (
	"testing"

	"chimera/internal/genome"
)

func TestPacketLengthShapeHitsBuckets(t *testing.T) {
	var client, server *PacketSession
	var found bool
	for i := 0; i < 40; i++ {
		g, err := genome.Generate(packetSeed(90+i), 0)
		if err != nil {
			t.Fatal(err)
		}
		if g.AppRecord.Padding.Mode == genome.PaddingNone {
			continue
		}
		cp, err := Compile(g, packetSeed(190+i))
		if err != nil {
			t.Fatal(err)
		}
		c, err := NewPacketSession(cp, genome.DirClient, cp.Bootstrap.C2S, cp.Bootstrap.S2C)
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewPacketSession(cp, genome.DirServer, cp.Bootstrap.C2S, cp.Bootstrap.S2C)
		if err != nil {
			t.Fatal(err)
		}
		c.SetShapeBuckets(DefaultShapeBuckets)
		client, server, found = c, s, true
		break
	}
	if !found {
		t.Skip("no padded app-record genome in seed range")
	}

	payload := []byte{0x45, 0, 1, 2, 3, 4, 5, 6}
	frame, err := client.Encode(payload)
	if err != nil {
		t.Fatal(err)
	}
	n := len(frame)
	inBucket := false
	for _, b := range DefaultShapeBuckets {
		if n == b {
			inBucket = true
			break
		}
	}
	if !inBucket && n <= DefaultShapeBuckets[len(DefaultShapeBuckets)-1] {
		t.Fatalf("shaped frame length %d is not on the ladder %v", n, DefaultShapeBuckets)
	}

	msg, err := server.Decode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if string(msg.Payload) != string(payload) {
		t.Fatalf("payload mismatch after shaping: %v", msg.Payload)
	}
}
