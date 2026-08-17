package netpkt

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestEchoRequestRoundTripFields(t *testing.T) {
	src := net.IPv4(10, 99, 0, 2)
	dst := net.IPv4(10, 99, 0, 1)
	pkt, err := EchoRequest(src, dst, 0x1122, 7, []byte(ProbeMagic))
	if err != nil {
		t.Fatal(err)
	}
	if pkt[0] != 0x45 {
		t.Fatalf("ver/ihl=%#x", pkt[0])
	}
	if pkt[9] != ipProtoICMP {
		t.Fatalf("proto=%d", pkt[9])
	}
	if checksum(pkt[:20]) != 0 {
		t.Fatal("IPv4 header checksum invalid")
	}
	if checksum(pkt[20:]) != 0 {
		t.Fatal("ICMP checksum invalid")
	}
	gotSrc, gotDst, ok := IPv4HeaderSrcDst(pkt)
	if !ok || !gotSrc.Equal(src) || !gotDst.Equal(dst) {
		t.Fatalf("src/dst %s -> %s", gotSrc, gotDst)
	}

	kind, ok := MatchProbe(pkt, pkt, src, dst, 0x1122, 7)
	if !ok || kind != ProbeEcho {
		t.Fatalf("echo match: kind=%s ok=%v", kind, ok)
	}

	reply := bytes.Clone(pkt)
	reply[20] = icmpEchoReply
	copy(reply[12:16], dst.To4())
	copy(reply[16:20], src.To4())
	reply[10], reply[11] = 0, 0
	binary.BigEndian.PutUint16(reply[10:12], checksum(reply[:20]))
	reply[22], reply[23] = 0, 0
	binary.BigEndian.PutUint16(reply[22:24], checksum(reply[20:]))

	kind, ok = MatchProbe(pkt, reply, src, dst, 0x1122, 7)
	if !ok || kind != ProbeICMPReply {
		t.Fatalf("icmp-reply match: kind=%s ok=%v", kind, ok)
	}
}

func TestGatewayForClient(t *testing.T) {
	gw, err := GatewayForClient("10.99.0.2")
	if err != nil {
		t.Fatal(err)
	}
	if gw != "10.99.0.1" {
		t.Fatalf("gw=%s", gw)
	}
	if _, err := GatewayForClient("::1"); err == nil {
		t.Fatal("IPv6 accepted")
	}
}

func TestHostFromAddr(t *testing.T) {
	if got := HostFromAddr("203.0.113.10:4789"); got != "203.0.113.10" {
		t.Fatalf("got %s", got)
	}
	if got := HostFromAddr("[::1]:4789"); got != "::1" {
		t.Fatalf("got %s", got)
	}
	if got := HostFromAddr("vpn.example"); got != "vpn.example" {
		t.Fatalf("got %s", got)
	}
}

func TestMatchProbeRejectsJunk(t *testing.T) {
	src := net.IPv4(10, 99, 0, 2)
	dst := net.IPv4(10, 99, 0, 1)
	pkt, err := EchoRequest(src, dst, 1, 1, []byte(ProbeMagic))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := MatchProbe(pkt, []byte{0x45, 0, 1, 2}, src, dst, 1, 1); ok {
		t.Fatal("junk matched")
	}
}
