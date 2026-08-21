package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestEvaluateFEPFirstDatagram(t *testing.T) {
	cover := []byte("ABCDEFGHIJKLMNOPQRSTUVWX")
	high := bytes.Repeat([]byte{0x0f}, 200)
	chimera := append(cover, high...)
	blocked := bytes.Repeat([]byte{0x0f}, 256)
	pkts := []datum{
		{tsUs: 0, flow: "a", payload: chimera},
		{tsUs: 5_000, flow: "a", payload: chimera},
		{tsUs: 1_000, flow: "b", payload: blocked},
	}
	rep := evaluate(pkts)
	if rep.Flows != 2 || rep.FirstExempt != 1 || rep.FirstBlocked != 1 {
		t.Fatalf("%+v", rep)
	}
	if rep.Rules["ex2"] != 1 || rep.Rules["blocked"] != 1 {
		t.Fatalf("rules %+v", rep.Rules)
	}
}

func TestReadEthernetUDPPcap(t *testing.T) {
	payload := append([]byte("ABCDEF"), bytes.Repeat([]byte{0x0f}, 20)...)
	raw := writeEthernetPcap(t, 4789, payload)
	pkts, err := readUDPPayloads(bytes.NewReader(raw), 4789)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkts) != 1 {
		t.Fatalf("got %d packets", len(pkts))
	}
	if !bytes.Equal(pkts[0].payload, payload) {
		t.Fatalf("payload mismatch %x", pkts[0].payload)
	}
	rep := evaluate(pkts)
	if rep.FirstExempt != 1 {
		t.Fatalf("want exempt first datagram: %+v", rep)
	}
}

func writeEthernetPcap(t *testing.T, port int, payload []byte) []byte {
	t.Helper()
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	frameLen := 14 + ipLen
	buf := bytes.NewBuffer(nil)
	var hdr [24]byte
	binary.LittleEndian.PutUint32(hdr[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(hdr[4:6], 2)
	binary.LittleEndian.PutUint16(hdr[6:8], 4)
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)
	binary.LittleEndian.PutUint32(hdr[20:24], 1)
	buf.Write(hdr[:])
	var rec [16]byte
	binary.LittleEndian.PutUint32(rec[8:12], uint32(frameLen))
	binary.LittleEndian.PutUint32(rec[12:16], uint32(frameLen))
	buf.Write(rec[:])

	eth := make([]byte, 14)
	eth[12], eth[13] = 0x08, 0x00
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], uint16(ipLen))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{10, 0, 0, 1})
	copy(ip[16:20], []byte{10, 0, 0, 2})
	udp := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:2], 12345)
	binary.BigEndian.PutUint16(udp[2:4], uint16(port))
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	buf.Write(eth)
	buf.Write(ip)
	buf.Write(udp)
	return buf.Bytes()
}
