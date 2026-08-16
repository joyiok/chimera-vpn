package compiler

import (
	"bytes"
	"math/bits"
)

// FEPExemption implements the GFW fully-encrypted-traffic detector inferred
// by Wu et al., USENIX Security 2023 (gfw.report): the censor does not define
// "fully encrypted"; it exempts the first payload of a flow if any of five
// heuristics match and blocks the rest. CHIMERA is UDP, but the same first-
// datagram tests are the right regression target if that pipeline is ever
// pointed at UDP or at a TCP port-forward of this protocol.
//
// Returns exempt=true and the firing rule name ("ex1"…"ex5") when the packet
// would be allowed through. exempt=false means the inferred detector would
// treat the payload as fully encrypted.
func FEPExemption(pkt []byte) (exempt bool, rule string) {
	if len(pkt) == 0 {
		return true, "empty"
	}

	// Ex1: popcount/len ≤ 3.4 or ≥ 4.6 set-bits per byte.
	ones := 0
	for _, b := range pkt {
		ones += bits.OnesCount8(b)
	}
	ratio := float64(ones) / float64(len(pkt))
	if ratio <= 3.4 || ratio >= 4.6 {
		return true, "ex1"
	}

	// Ex2: first six (or more) bytes are printable ASCII [0x20, 0x7e].
	if len(pkt) >= 6 {
		ok := true
		for _, b := range pkt[:6] {
			if !printableASCII(b) {
				ok = false
				break
			}
		}
		if ok {
			return true, "ex2"
		}
	}

	// Ex3: more than 50% of bytes are printable ASCII.
	printable := 0
	for _, b := range pkt {
		if printableASCII(b) {
			printable++
		}
	}
	if printable*2 > len(pkt) {
		return true, "ex3"
	}

	// Ex4: more than 20 contiguous printable ASCII bytes.
	run := 0
	for _, b := range pkt {
		if printableASCII(b) {
			run++
			if run > 20 {
				return true, "ex4"
			}
		} else {
			run = 0
		}
	}

	// Ex5: first bytes match TLS or HTTP fingerprints.
	if looksLikeTLS(pkt) {
		return true, "ex5"
	}
	if looksLikeHTTP(pkt) {
		return true, "ex5"
	}
	return false, ""
}

func printableASCII(b byte) bool { return b >= 0x20 && b <= 0x7e }

func looksLikeTLS(pkt []byte) bool {
	// TLS record: ContentType handshake (0x16) + version 0x03 0x01..0x04.
	return len(pkt) >= 3 && pkt[0] == 0x16 && pkt[1] == 0x03 && pkt[2] <= 0x04
}

func looksLikeHTTP(pkt []byte) bool {
	for _, p := range httpMethodPrefixes {
		if bytes.HasPrefix(pkt, p) {
			return true
		}
	}
	return false
}

// httpMethodPrefixes are the Ex5 fingerprints we must not emit as a cover
// (being classified as HTTP evades FEP but lands in the HTTP DPI pipeline).
var httpMethodPrefixes = [][]byte{
	[]byte("GET "),
	[]byte("PUT "),
	[]byte("POST"),
	[]byte("HEAD"),
	[]byte("HTTP"),
	[]byte("CONN"),
	[]byte("OPTI"),
	[]byte("PATC"),
	[]byte("DELE"),
	[]byte("SSH-"),
}
