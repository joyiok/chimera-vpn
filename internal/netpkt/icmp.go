package netpkt

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	// ProbeMagic is the ICMP payload used by `chimerac -check`.
	ProbeMagic = "CHIMERA-CHECK"

	icmpEchoRequest = 8
	icmpEchoReply   = 0
	ipProtoICMP     = 1
)

// EchoRequest builds a raw IPv4 ICMP echo request (20-byte header, no options).
func EchoRequest(src, dst net.IP, id, seq uint16, payload []byte) ([]byte, error) {
	src4 := src.To4()
	dst4 := dst.To4()
	if src4 == nil || dst4 == nil {
		return nil, fmt.Errorf("echo request requires IPv4 endpoints")
	}
	icmpLen := 8 + len(payload)
	total := 20 + icmpLen
	pkt := make([]byte, total)

	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	binary.BigEndian.PutUint16(pkt[4:6], id)
	pkt[8] = 64
	pkt[9] = ipProtoICMP
	copy(pkt[12:16], src4)
	copy(pkt[16:20], dst4)
	binary.BigEndian.PutUint16(pkt[10:12], checksum(pkt[:20]))

	icmp := pkt[20:]
	icmp[0] = icmpEchoRequest
	binary.BigEndian.PutUint16(icmp[4:6], id)
	binary.BigEndian.PutUint16(icmp[6:8], seq)
	copy(icmp[8:], payload)
	binary.BigEndian.PutUint16(icmp[2:4], checksum(icmp))
	return pkt, nil
}

// ProbeKind classifies a packet received in response to an EchoRequest.
type ProbeKind string

const (
	ProbeEcho      ProbeKind = "echo"
	ProbeICMPReply ProbeKind = "icmp-reply"
)

// MatchProbe reports whether got is a userspace echo of sent, or a kernel
// ICMP echo-reply for that request (TUN path).
func MatchProbe(sent, got []byte, client, gateway net.IP, id, seq uint16) (ProbeKind, bool) {
	if len(got) == 0 {
		return "", false
	}
	if bytes.Equal(sent, got) {
		return ProbeEcho, true
	}
	if isICMPEchoReply(got, gateway, client, id, seq) {
		return ProbeICMPReply, true
	}
	return "", false
}

func isICMPEchoReply(pkt []byte, wantSrc, wantDst net.IP, id, seq uint16) bool {
	if len(pkt) < 28 || pkt[0]>>4 != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0f) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}
	if pkt[9] != ipProtoICMP {
		return false
	}
	src := net.IP(pkt[12:16])
	dst := net.IP(pkt[16:20])
	if !src.Equal(wantSrc.To4()) || !dst.Equal(wantDst.To4()) {
		return false
	}
	icmp := pkt[ihl:]
	if icmp[0] != icmpEchoReply {
		return false
	}
	gotID := binary.BigEndian.Uint16(icmp[4:6])
	gotSeq := binary.BigEndian.Uint16(icmp[6:8])
	return gotID == id && gotSeq == seq
}

func checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}
